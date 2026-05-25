package com.ss.android.ugc.aweme;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.TraceHook;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.backend.BackendFactory;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.hook.hookzz.HookEntryInfo;
import com.github.unidbg.hook.hookzz.HookZz;
import com.github.unidbg.hook.hookzz.HookZzArm64RegisterContext;
import com.github.unidbg.hook.hookzz.IHookZz;
import com.github.unidbg.hook.hookzz.WrapCallback;
import com.github.unidbg.listener.TraceCodeListener;
import com.github.unidbg.linux.ARM64SyscallHandler;
import com.github.unidbg.linux.android.AndroidARM64Emulator;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.unix.UnixSyscallHandler;
import com.github.unidbg.unwind.Unwinder;
import com.sun.jna.Pointer;
import capstone.api.Instruction;
import java.io.File;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MainActivity {

    // 用于静默丢弃 trace 输出的空打印流。
    private static final PrintStream DEV_NULL = new PrintStream(new OutputStream() {
        @Override
        // 忽略所有写入字节。
        public void write(int b) {
        }
    });
    // 是否安装组件插入点 hook。
    private static final boolean ENABLE_COMPONENT_HOOK = true ;
    // 是否安装单步调试断点。
    private static final boolean Open_break = false;
    // 手工指定固定毫秒时间戳，设为 null 时走自动推断。
    private static final Long FIXED_TIME_MILLIS = 1779160424642l;
    // 是否从请求参数中自动提取固定时间戳。
    private static final boolean AUTO_FIX_TIME_FROM_REQUEST = true;
    // 是否同步改写 URL 和 header 里的时间字段。
    private static final boolean REWRITE_REQUEST_TIME_FIELDS = true;
    // 是否全局监控指定 value 缓冲区的读写。
    private static final boolean ENABLE_GLOBAL_VALUE_TRACE = true;
    // 需要全局监控的 value 缓冲区起始地址。
    private static final long GLOBAL_VALUE_TRACE_ADDRESS = 0x13104b00L;
    // 需要全局监控的 value 缓冲区长度。
    private static final int GLOBAL_VALUE_TRACE_SIZE = 0x35;
    // 测试 so 和输入文件所在目录。
    private static final File SO_DIR =
            new File("unidbg-android/src/test/java/com/ss/android/ugc/aweme");
    // 保存回调 URL 输入文本的文件。
    private static final File CALLBACK_URL_FILE =
            new File("unidbg-android/src/test/java/com/ss/android/ugc/aweme/mssdk_callback_url.txt");
    // 保存回调 header 文本的文件。
    private static final File CALLBACK_HEADERS_FILE =
            new File("unidbg-android/src/test/java/com/ss/android/ugc/aweme/mssdk_callback_headers.txt");
    // 通用 header 插入函数偏移。
    private static final long METASEC_COMPONENT_OFFSET = 0x2b7724L;
    // 直接回调 metasec 主入口偏移。
    private static final long METASEC_CALLBACK_OFFSET = 0x2c6858L;
    // 调试断点安装的函数偏移。
    private static final long Break_offset = 0x2ce7fc;
    // metasec prepare 初始化函数偏移。
    private static final long METASEC_PREPARE_OFFSET = 0x27f9d4L;
    // 全局 dispatch 对象槽位地址偏移。
    private static final long METASEC_GLOBAL_DISPATCH_PTR_OFFSET = 0x58f6a0L;
    // 匹配 URL 中 _rticket 参数的正则。
    private static final Pattern RTICKET_PATTERN = Pattern.compile("([?&])_rticket=(\\d+)");
    // 匹配 URL 中 ts 参数的正则。
    private static final Pattern TS_PATTERN = Pattern.compile("([?&])ts=(\\d+)");

    // 程序入口，构造环境后执行 direct callback 测试。
    public static void main(String[] args) {
        long start = System.currentTimeMillis();
        MainActivity mainActivity = new MainActivity();
        System.out.println("load offset=" + (System.currentTimeMillis() - start) + "ms");
        mainActivity.testDirectMetasecCallback();
    }

    // 当前测试使用的 64 位 Android 模拟器。
    private final FixedClockAndroidARM64Emulator emulator;
    // 已加载的 libmetasec_ml.so 模块对象。
    private final Module metasecModule;
    // 手工分配的内存块列表，便于统一持有生命周期。
    private final List<MemoryBlock> manualBlocks = new ArrayList<>();
    // 只打印一次 X-Gorgon 原生调用栈的标记。
    private boolean gorgonCallstackPrinted;

    // 构造模拟器、依赖库和 metasec 主模块。
    private MainActivity() {
        List<BackendFactory> backendFactories = new ArrayList<>();
        backendFactories.add(new Unicorn2Factory(true));
        emulator = new FixedClockAndroidARM64Emulator(null, null, backendFactories);
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));

        preloadIfExists("libc++_shared.so");
        preloadIfExists("libttboringssl.so");
        preloadIfExists("libttcrypto.so");
        preloadIfExists("libandroid.so");

        metasecModule = emulator.loadLibrary(new File(SO_DIR, "libmetasec_ml.so"));
        if (ENABLE_COMPONENT_HOOK) {
            installMetasecComponentHook(metasecModule);
        }
        if (Open_break) {
            installBreakpoint();
        }
    }

    // 预加载存在的依赖 so，避免主库解析失败。
    private void preloadIfExists(String soName) {
        File file = new File(SO_DIR, soName);
        if (file.isFile()) {
            emulator.loadLibrary(file);
        }
    }

    // 直接调用 metasec native 回调并打印返回结果。
    private void testDirectMetasecCallback() {
        String url = loadText(CALLBACK_URL_FILE).trim();
        String headerBlob = decodeEscapedCrlf(loadText(CALLBACK_HEADERS_FILE).trim());
        Long fixedTimeMillis = resolveFixedTimeMillis(url, headerBlob);
        if (fixedTimeMillis != null) {
            emulator.getFixedClockSyscallHandler().setFixedTimeMillis(fixedTimeMillis);
            if (REWRITE_REQUEST_TIME_FIELDS) {
                url = rewriteRequestTimeFields(url, fixedTimeMillis);
                headerBlob = rewriteHeaderTimeFields(headerBlob, fixedTimeMillis);
            }
            System.out.printf("fixed timestamp enabled: %d (sec=%d)%n", fixedTimeMillis, fixedTimeMillis / 1000L);
        }
        ArrayDeque<String> trace = new ArrayDeque<>();
        TraceHook traceHook = emulator.traceCode(
                metasecModule.base,
                metasecModule.base + metasecModule.size,
                new TraceCodeListener() {
                    @Override
                    public void onInstruction(Emulator<?> emulator, long address, Instruction insn) {
                        if (trace.size() >= 64) {
                            trace.removeFirst();
                        }
                        trace.addLast(String.format("0x%x: %s", address, insn));
                    }
                }
        );
        traceHook.setRedirect(DEV_NULL);
        TraceHook globalValueReadTrace = null;
        TraceHook globalValueWriteTrace = null;
        if (ENABLE_GLOBAL_VALUE_TRACE) {
            long traceBegin = GLOBAL_VALUE_TRACE_ADDRESS;
            long traceEnd = GLOBAL_VALUE_TRACE_ADDRESS + GLOBAL_VALUE_TRACE_SIZE - 1L;
            System.out.printf("global value trace enabled: [0x%x, 0x%x] size=0x%x%n",
                    traceBegin, traceEnd, GLOBAL_VALUE_TRACE_SIZE);
            globalValueReadTrace = emulator.traceRead(traceBegin, traceEnd);
            globalValueWriteTrace = emulator.traceWrite(traceBegin, traceEnd);
        }

        dumpMetasecDispatchPtr("before prepare");
        Number prep = Module.emulateFunction(emulator, metasecModule.base + METASEC_PREPARE_OFFSET);
        System.out.printf("direct-callback prepare ret=0x%x%n", prep.longValue());
        dumpMetasecDispatchPtr("after prepare");
        installManualMetasecDispatchStub();
        dumpMetasecDispatchPtr("after manual dispatch stub");

        System.out.println("direct-callback url=" + url);
        System.out.println("direct-callback headerBlob=\n" + headerBlob);

        try {
            Number ret = Module.emulateFunction(
                    emulator,
                    metasecModule.base + METASEC_CALLBACK_OFFSET,
                    url,
                    headerBlob
            );
            long retPtr = ret.longValue();
            System.out.printf("direct-callback ret=0x%x%n", retPtr);
            if (retPtr <= 0) {
                System.out.println("direct-callback result=<invalid pointer / failure sentinel>");
                dumpTraceTail(trace);
                return;
            }

            UnidbgPointer pointer = UnidbgPointer.pointer(emulator, retPtr);
            String result = pointer == null ? null : pointer.getString(0);
            System.out.println("direct-callback result=\n" + result);
        } finally {
            if (globalValueReadTrace != null) {
                globalValueReadTrace.stopTrace();
            }
            if (globalValueWriteTrace != null) {
                globalValueWriteTrace.stopTrace();
            }
            traceHook.stopTrace();
        }
    }

    // 安装 header 组件插入函数 hook，用于观察 X-Gorgon 等字段。
    private void installMetasecComponentHook(Module module) {
        long target = module.base + METASEC_COMPONENT_OFFSET;
        IHookZz hookZz = HookZz.getInstance(emulator);
        hookZz.enable_arm_arm64_b_branch();
        hookZz.wrap(target, new WrapCallback<HookZzArm64RegisterContext>() {
            @Override
            // 进入组件插入函数前打印 key/value 及关键调用栈。
            public void preCall(Emulator<?> emulator, HookZzArm64RegisterContext ctx, HookEntryInfo info) {
                UnidbgPointer mapCtx = ctx.getPointerArg(0);
                UnidbgPointer keyRef = ctx.getPointerArg(1);
                UnidbgPointer valueRef = ctx.getPointerArg(2);
                String keyText = readMssdkStringRefText(keyRef);
                System.out.printf("[metasec+0x%x] lr=%s mapCtx=%s%n", METASEC_COMPONENT_OFFSET, ctx.getLRPointer(), mapCtx);
                System.out.println("  key   => " + describeMssdkStringRef(keyRef));
                System.out.println("  value => " + describeMssdkStringRef(valueRef));
                if (!gorgonCallstackPrinted && "X-GORGON".equalsIgnoreCase(keyText)) {
                    gorgonCallstackPrinted = true;
                    System.out.println("  X-Gorgon native callstack:");
                    dumpNativeCallstack(30);
                }
            }
        });
        hookZz.disable_arm_arm64_b_branch();
    }

    // 在目标偏移安装临时断点并打印 PC/LR/调用栈。
    private void installBreakpoint() {
        emulator.attach().addBreakPoint(metasecModule, Break_offset, (emu, address) -> {
            System.out.printf("[bp data] hit address=0x%x pc=%s lr=%s%n",
                    address,
                    emu.getContext().getPCPointer(),
                    emu.getContext().getLRPointer());
            dumpNativeCallstack(30);
            return false;
        });
        System.out.printf("installed breakpoint at libmetasec_ml.so+0x%x%n", Break_offset);
    }

    // 打印当前线程的原生调用栈。
    private void dumpNativeCallstack(int maxDepth) {
        try {
            Unwinder unwinder = emulator.getUnwinder();
            for (com.github.unidbg.unwind.Frame frame : unwinder.getFrames(maxDepth)) {
                long pc = frame.ip == null ? 0 : frame.ip.peer;
                Module module = emulator.getMemory().findModuleByAddress(pc);
                if (module != null) {
                    System.out.printf("    0x%x %s+0x%x%n", pc, module.name, pc - module.base);
                } else {
                    System.out.printf("    0x%x%n", pc);
                }
            }
        } catch (Exception e) {
            System.out.println("    <callstack failed: " + e.getMessage() + ">");
        }
    }

    // 将 mssdk 的字符串引用结构格式化为可读描述。
    private String describeMssdkStringRef(UnidbgPointer ref) {
        if (ref == null) {
            return "null";
        }
        try {
            int alloc = ref.getInt(8);
            int len = ref.getInt(12);
            Pointer dataPtr = ref.getPointer(16);
            long dataPeer = UnidbgPointer.nativeValue(dataPtr);
            UnidbgPointer data = UnidbgPointer.pointer(emulator, dataPeer);
            return String.format("ref=%s alloc=%d len=%d data=%s text=%s",
                    ref, alloc, len, data, readSizedUtf8(data, len));
        } catch (Exception e) {
            return "ref=" + ref + " <decode failed: " + e.getMessage() + ">";
        }
    }

    // 读取 mssdk 字符串引用结构里的实际文本。
    private String readMssdkStringRefText(UnidbgPointer ref) {
        if (ref == null) {
            return null;
        }
        try {
            int len = ref.getInt(12);
            Pointer dataPtr = ref.getPointer(16);
            UnidbgPointer data = UnidbgPointer.pointer(emulator, UnidbgPointer.nativeValue(dataPtr));
            if (data == null) {
                return null;
            }
            int size = Math.max(0, Math.min(len, 0x200));
            return new String(size == 0 ? new byte[0] : data.getByteArray(0, size), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    // 按给定长度读取 UTF-8 文本并转义换行。
    private String readSizedUtf8(UnidbgPointer data, int len) {
        if (data == null) {
            return "null";
        }
        if (len < 0) {
            return "<neg-len:" + len + ">";
        }
        int size = Math.min(len, 0x200);
        byte[] bytes = size == 0 ? new byte[0] : data.getByteArray(0, size);
        return new String(bytes, StandardCharsets.UTF_8)
                .replace("\r", "\\r")
                .replace("\n", "\\n");
    }

    // 从磁盘读取整个文本文件。
    private String loadText(File file) {
        try {
            return new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load text file: " + file, e);
        }
    }

    // 将文件中的转义 \\r\\n 还原成真实换行。
    private String decodeEscapedCrlf(String text) {
        return text.replace("\\r\\n", "\r\n");
    }

    // 解析本次调用应使用的固定毫秒时间戳。
    private Long resolveFixedTimeMillis(String url, String headerBlob) {
        if (FIXED_TIME_MILLIS != null) {
            return FIXED_TIME_MILLIS;
        }
        if (!AUTO_FIX_TIME_FROM_REQUEST) {
            return null;
        }

        Long value = extractQueryParamAsLong(url, RTICKET_PATTERN);
        if (value != null) {
            return value;
        }
        value = extractHeaderValueAsLong(headerBlob, "x-ss-req-ticket");
        if (value != null) {
            return value;
        }
        value = extractHeaderValueAsLong(headerBlob, "activity_now_client");
        if (value != null) {
            return value;
        }
        value = extractQueryParamAsLong(url, TS_PATTERN);
        return value == null ? null : value * 1000L;
    }

    // 按正则从 URL 查询串中提取 long 值。
    private Long extractQueryParamAsLong(String url, Pattern pattern) {
        Matcher matcher = pattern.matcher(url);
        if (!matcher.find()) {
            return null;
        }
        return Long.parseLong(matcher.group(2));
    }

    // 从交替的 header key/value 文本中提取 long 值。
    private Long extractHeaderValueAsLong(String headerBlob, String key) {
        String[] lines = headerBlob.split("\\r?\\n");
        for (int i = 0; i + 1 < lines.length; i += 2) {
            if (key.equalsIgnoreCase(lines[i].trim())) {
                try {
                    return Long.parseLong(lines[i + 1].trim());
                } catch (NumberFormatException ignored) {
                    return null;
                }
            }
        }
        return null;
    }

    // 用固定时间改写请求 URL 中的时间参数。
    private String rewriteRequestTimeFields(String url, long fixedTimeMillis) {
        String updated = replaceQueryLongParam(url, RTICKET_PATTERN, "_rticket", fixedTimeMillis);
        return replaceQueryLongParam(updated, TS_PATTERN, "ts", fixedTimeMillis / 1000L);
    }

    // 替换 URL 查询串里指定 key 的 long 值。
    private String replaceQueryLongParam(String text, Pattern pattern, String key, long value) {
        Matcher matcher = pattern.matcher(text);
        if (!matcher.find()) {
            return text;
        }
        return matcher.replaceAll("$1" + key + "=" + value);
    }

    // 用固定时间改写 header 文本中的时间字段。
    private String rewriteHeaderTimeFields(String headerBlob, long fixedTimeMillis) {
        String separator = headerBlob.contains("\r\n") ? "\r\n" : "\n";
        String[] lines = headerBlob.split("\\r?\\n", -1);
        for (int i = 0; i + 1 < lines.length; i += 2) {
            String key = lines[i].trim();
            if ("x-ss-req-ticket".equalsIgnoreCase(key) || "activity_now_client".equalsIgnoreCase(key)) {
                lines[i + 1] = Long.toString(fixedTimeMillis);
            }
        }
        return String.join(separator, lines);
    }

    // 安装一套伪造的全局 dispatch/result 对象以通过 native 检查。
    private void installManualMetasecDispatchStub() {
        UnidbgPointer globalClass = allocateBlock(0x40);
        UnidbgPointer globalObj = allocateBlock(0x20);
        globalObj.setPointer(0, globalClass);

        UnidbgPointer resultClass = allocateBlock(0x800);
        UnidbgPointer resultObj = allocateBlock(0x20);
        resultObj.setPointer(0, resultClass);
        resultObj.setPointer(0x10, globalObj);

        UnidbgPointer fakeHandle30 = allocateBlock(0x20);
        UnidbgPointer fakeHandle388 = allocateBlock(0x20);
        UnidbgPointer fakeHandle398 = allocateBlock(0x20);
        UnidbgPointer fakeHandle108 = allocateBlock(0x20);
        UnidbgPointer fakeHandle118 = allocateBlock(0x20);
        UnidbgPointer fakeHandle568 = allocateBlock(0x20);
        UnidbgPointer fakeStringSerializableHttpCookie =
                allocateCString("com.bytedance.frameworks.baselib.network.http.impl.SerializableHttpCookie");
        UnidbgPointer fakeStringProcStat = allocateCString("/proc/26770/stat");
        final int[] result548Index = {0};

        UnidbgPointer globalMethod28 = emulator.getSvcMemory().registerSvc(new Arm64Svc("metasec_fake_global_28") {
            @Override
            // 模拟全局对象的空操作方法。
            public long handle(Emulator<?> emulator) {
                return 0;
            }
        });
        UnidbgPointer globalMethod30 = emulator.getSvcMemory().registerSvc(new Arm64Svc("metasec_fake_global_30") {
            @Override
            // 按 mode 返回伪造的结果对象。
            public long handle(Emulator<?> emulator) {
                UnidbgPointer out = emulator.getContext().getPointerArg(1);
                long mode = emulator.getContext().getLongArg(2);
                if (mode == 0x10006L && out != null) {
                    out.setPointer(0, resultObj);
                    return 0;
                }
                return 0;
            }
        });
        UnidbgPointer resultMethod20 = emulator.getSvcMemory().registerSvc(new Arm64Svc("metasec_fake_result_20") {
            @Override
            // 模拟结果对象的空操作方法。
            public long handle(Emulator<?> emulator) {
                return 0;
            }
        });
        UnidbgPointer resultMethod28 = emulator.getSvcMemory().registerSvc(new Arm64Svc("metasec_fake_result_28") {
            @Override
            // 模拟结果对象的空操作方法。
            public long handle(Emulator<?> emulator) {
                return 0;
            }
        });
        UnidbgPointer resultMethod30 = emulator.getSvcMemory().registerSvc(new Arm64Svc("metasec_fake_result_30") {
            @Override
            // 返回伪造的 handle30 对象。
            public long handle(Emulator<?> emulator) {
                return UnidbgPointer.nativeValue(fakeHandle30);
            }
        });
        UnidbgPointer resultMethod388 = emulator.getSvcMemory().registerSvc(new Arm64Svc("metasec_fake_result_388") {
            @Override
            // 返回伪造的 handle388 对象。
            public long handle(Emulator<?> emulator) {
                return UnidbgPointer.nativeValue(fakeHandle388);
            }
        });
        UnidbgPointer resultMethod398 = emulator.getSvcMemory().registerSvc(new Arm64Svc("metasec_fake_result_398") {
            @Override
            // 返回伪造的 handle398 对象。
            public long handle(Emulator<?> emulator) {
                return UnidbgPointer.nativeValue(fakeHandle398);
            }
        });
        UnidbgPointer resultMethod108 = emulator.getSvcMemory().registerSvc(new Arm64Svc("metasec_fake_result_108") {
            @Override
            // 返回伪造的 handle108 对象。
            public long handle(Emulator<?> emulator) {
                return UnidbgPointer.nativeValue(fakeHandle108);
            }
        });
        UnidbgPointer resultMethod118 = emulator.getSvcMemory().registerSvc(new Arm64Svc("metasec_fake_result_118") {
            @Override
            // 返回伪造的 handle118 对象。
            public long handle(Emulator<?> emulator) {
                return UnidbgPointer.nativeValue(fakeHandle118);
            }
        });
        UnidbgPointer resultMethod548 = emulator.getSvcMemory().registerSvc(new Arm64Svc("metasec_fake_result_548") {
            @Override
            // 轮流返回两个字符串对象供 native 读取。
            public long handle(Emulator<?> emulator) {
                int index = result548Index[0]++;
                return UnidbgPointer.nativeValue((index & 1) == 0
                        ? fakeStringSerializableHttpCookie
                        : fakeStringProcStat);
            }
        });
        UnidbgPointer resultMethod550 = emulator.getSvcMemory().registerSvc(new Arm64Svc("metasec_fake_result_550") {
            @Override
            // 返回固定布尔真值。
            public long handle(Emulator<?> emulator) {
                return 1;
            }
        });
        UnidbgPointer resultMethod558 = emulator.getSvcMemory().registerSvc(new Arm64Svc("metasec_fake_result_558") {
            @Override
            // 返回固定枚举值 0xb。
            public long handle(Emulator<?> emulator) {
                return 0xb;
            }
        });
        UnidbgPointer resultMethod568 = emulator.getSvcMemory().registerSvc(new Arm64Svc("metasec_fake_result_568") {
            @Override
            // 返回伪造的 handle568 对象。
            public long handle(Emulator<?> emulator) {
                return UnidbgPointer.nativeValue(fakeHandle568);
            }
        });
        UnidbgPointer resultMethodB8 = emulator.getSvcMemory().registerSvc(new Arm64Svc("metasec_fake_result_b8") {
            @Override
            // 返回固定布尔真值。
            public long handle(Emulator<?> emulator) {
                return 1;
            }
        });
        UnidbgPointer resultMethod88 = emulator.getSvcMemory().registerSvc(new Arm64Svc("metasec_fake_result_88") {
            @Override
            // 返回固定零值。
            public long handle(Emulator<?> emulator) {
                return 0;
            }
        });
        UnidbgPointer resultMethod720 = emulator.getSvcMemory().registerSvc(new Arm64Svc("metasec_fake_result_720") {
            @Override
            // 返回固定零值。
            public long handle(Emulator<?> emulator) {
                return 0;
            }
        });

        globalClass.setPointer(0x28, globalMethod28);
        globalClass.setPointer(0x30, globalMethod30);

        resultClass.setPointer(0x20, resultMethod20);
        resultClass.setPointer(0x28, resultMethod28);
        resultClass.setPointer(0x30, resultMethod30);
        resultClass.setPointer(0x88, resultMethod88);
        resultClass.setPointer(0xb8, resultMethodB8);
        resultClass.setPointer(0x108, resultMethod108);
        resultClass.setPointer(0x118, resultMethod118);
        resultClass.setPointer(0x388, resultMethod388);
        resultClass.setPointer(0x398, resultMethod398);
        resultClass.setPointer(0x548, resultMethod548);
        resultClass.setPointer(0x550, resultMethod550);
        resultClass.setPointer(0x558, resultMethod558);
        resultClass.setPointer(0x568, resultMethod568);
        resultClass.setPointer(0x720, resultMethod720);

        UnidbgPointer slot = UnidbgPointer.pointer(emulator, metasecModule.base + METASEC_GLOBAL_DISPATCH_PTR_OFFSET);
        if (slot == null) {
            throw new IllegalStateException("data_98f6a0 slot pointer is null");
        }
        slot.setPointer(0, globalObj);
        System.out.printf(
                "manual dispatch stub installed globalObj=%s globalClass=%s resultObj=%s resultClass=%s "
                        + "slot=%s slotValue=%s resultObj[0]=%s resultObj[0x10]=%s "
                        + "global[0x28]=%s global[0x30]=%s result[0x20]=%s result[0x28]=%s result[0x30]=%s "
                        + "result[0x88]=%s result[0xb8]=%s result[0x108]=%s result[0x118]=%s result[0x388]=%s "
                        + "result[0x398]=%s result[0x548]=%s result[0x550]=%s result[0x558]=%s result[0x568]=%s result[0x720]=%s%n",
                globalObj,
                globalClass,
                resultObj,
                resultClass,
                slot,
                slot.getPointer(0),
                resultObj.getPointer(0),
                resultObj.getPointer(0x10),
                globalClass.getPointer(0x28),
                globalClass.getPointer(0x30),
                resultClass.getPointer(0x20),
                resultClass.getPointer(0x28),
                resultClass.getPointer(0x30),
                resultClass.getPointer(0x88),
                resultClass.getPointer(0xb8),
                resultClass.getPointer(0x108),
                resultClass.getPointer(0x118),
                resultClass.getPointer(0x388),
                resultClass.getPointer(0x398),
                resultClass.getPointer(0x548),
                resultClass.getPointer(0x550),
                resultClass.getPointer(0x558),
                resultClass.getPointer(0x568),
                resultClass.getPointer(0x720)
        );
    }

    // 在模拟器堆上分配一块内存并记录下来。
    private UnidbgPointer allocateBlock(int size) {
        MemoryBlock block = emulator.getMemory().malloc(size, true);
        manualBlocks.add(block);
        return block.getPointer();
    }

    // 分配并写入一个以 \\0 结尾的 C 字符串。
    private UnidbgPointer allocateCString(String text) {
        byte[] bytes = (text + "\0").getBytes(StandardCharsets.UTF_8);
        UnidbgPointer pointer = allocateBlock(bytes.length);
        pointer.write(0, bytes, 0, bytes.length);
        return pointer;
    }

    // 打印全局 dispatch 槽位当前指针值。
    private void dumpMetasecDispatchPtr(String phase) {
        long addr = metasecModule.base + METASEC_GLOBAL_DISPATCH_PTR_OFFSET;
        UnidbgPointer p = UnidbgPointer.pointer(emulator, addr);
        Pointer valuePtr = p == null ? null : p.getPointer(0);
        long value = UnidbgPointer.nativeValue(valuePtr);
        System.out.printf("%s data_98f6a0 slot=%s value=0x%x%n", phase, p, value);
    }

    // 打印最近保留的指令 trace 尾部。
    private void dumpTraceTail(ArrayDeque<String> trace) {
        System.out.println("direct-callback trace tail:");
        for (String line : trace) {
            System.out.println("  " + line);
        }
    }

    // 为当前测试注入可固定时间的 Android ARM64 模拟器。
    private static final class FixedClockAndroidARM64Emulator extends AndroidARM64Emulator {

        // 当前模拟器绑定的固定时间 syscall handler。
        private FixedClockARM64SyscallHandler fixedClockSyscallHandler;

        // 构造支持固定时间的 ARM64 模拟器实例。
        private FixedClockAndroidARM64Emulator(String processName, File rootDir, List<BackendFactory> backendFactories) {
            super(processName, rootDir, backendFactories);
        }

        @Override
        // 创建可覆写 currentTimeMillis 的 syscall handler。
        protected UnixSyscallHandler<AndroidFileIO> createSyscallHandler(SvcMemory svcMemory) {
            fixedClockSyscallHandler = new FixedClockARM64SyscallHandler(svcMemory);
            return fixedClockSyscallHandler;
        }

        // 取回当前模拟器使用的固定时间 handler。
        private FixedClockARM64SyscallHandler getFixedClockSyscallHandler() {
            return fixedClockSyscallHandler;
        }
    }

    // 通过覆写 currentTimeMillis 固定 realtime 时间源。
    private static final class FixedClockARM64SyscallHandler extends ARM64SyscallHandler {

        // 当前生效的固定毫秒时间戳。
        private volatile Long fixedTimeMillis;

        // 构造固定时间版 ARM64 syscall handler。
        private FixedClockARM64SyscallHandler(SvcMemory svcMemory) {
            super(svcMemory);
        }

        // 更新当前 syscall handler 使用的固定时间。
        private void setFixedTimeMillis(Long fixedTimeMillis) {
            this.fixedTimeMillis = fixedTimeMillis;
        }

        @Override
        // 返回固定时间，没有配置时退回父类实现。
        protected long currentTimeMillis() {
            Long value = fixedTimeMillis;
            return value != null ? value : super.currentTimeMillis();
        }
    }
}
