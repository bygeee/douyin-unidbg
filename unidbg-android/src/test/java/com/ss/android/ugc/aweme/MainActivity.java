package com.ss.android.ugc.aweme;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.TraceHook;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendFactory;
import com.github.unidbg.arm.backend.CodeHook;
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
import org.apache.commons.codec.binary.Hex;
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
import unicorn.Arm64Const;

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
    private static final Long FIXED_TIME_MILLIS = 1779160424642L;
    // 是否从请求参数中自动提取固定时间戳。
    private static final boolean AUTO_FIX_TIME_FROM_REQUEST = true;
    // 是否同步改写 URL 和 header 里的时间字段。
    private static final boolean REWRITE_REQUEST_TIME_FIELDS = true;
    // 是否全局监控指定 value 缓冲区的读写。
    private static final boolean ENABLE_GLOBAL_VALUE_TRACE = true;
    // 是否打印全局 value 缓冲区的 read trace。
    private static final boolean ENABLE_GLOBAL_VALUE_READ_TRACE = false;
    // 是否打印全局 value 缓冲区的 write trace。
    private static final boolean ENABLE_GLOBAL_VALUE_WRITE_TRACE = true;
    // 是否监控最终 X-Gorgon 文本源缓冲区的写入。
    private static final boolean ENABLE_GORGON_SOURCE_BUFFER_TRACE = true;
    // 是否监控更早阶段暂存 X-Gorgon 值的内存区域写入。
    private static final boolean ENABLE_EARLY_GORGON_VALUE_TRACE = true;
    // 是否在执行到 sub_259154 时打印 *(arg2 + 8) 的源字符串。
    private static final boolean ENABLE_STRING_COPY_HOOK = false;
    // 是否在最终 memcpy 前直接打印 x1/src。
    private static final boolean ENABLE_GORGON_MEMCPY_SOURCE_HOOK = true;
    // 是否在命中 sub_257ae0 逐字节追加字符时打印一次调用栈。
    private static final boolean ENABLE_GORGON_CHAR_APPEND_CALLSTACK = true;
    // 是否打印组件插入点的 key/value 文本。
    private static final boolean ENABLE_LOG_COMPONENT_VALUES = true;
    // 是否打印 X-Gorgon 的原生调用栈。
    private static final boolean ENABLE_LOG_GORGON_CALLSTACK = true;
    // 是否打印 sub_259154 里 *(arg2+8) 的细节。
    private static final boolean ENABLE_LOG_STRING_COPY_DETAILS = false;
    // 是否打印 memcpy 前后的源地址与内容。
    private static final boolean ENABLE_LOG_GORGON_MEMCPY_ARGS = true;
    // 是否打印 memcpy 源地址前后的候选窗口。
    private static final boolean ENABLE_LOG_GORGON_SOURCE_CANDIDATES = true;
    // 是否打印 sub_2b7724 插入前的 key/value 对象。
    private static final boolean ENABLE_LOG_MAP_INSERT_DETAILS = true;
    // 是否分析 sub_2c20d4 的输入、KSA seed 和输出包。
    private static final boolean ENABLE_SUB_2C20D4_ANALYSIS = true;
    // 是否分析 sub_2c269c 中传给 sub_2c20d4 的 20 字节输入是如何逐段拼出来的。
    private static final boolean ENABLE_SUB_2C269C_INPUT_BUILD_ANALYSIS = true;
    // 需要全局监控的 value 缓冲区起始地址。
    private static final long GLOBAL_VALUE_TRACE_ADDRESS = 0x13104b00L;
    // 需要全局监控的 value 缓冲区长度。
    private static final int GLOBAL_VALUE_TRACE_SIZE = 0x35;
    // 最终 X-Gorgon 文本源缓冲区起始地址。
    private static final long GORGON_SOURCE_TRACE_ADDRESS = 0x13104b40L;
    // 最终 X-Gorgon 文本源缓冲区长度。
    private static final int GORGON_SOURCE_TRACE_SIZE = 0x35;
    // 需要监控的早期 X-Gorgon 暂存地址列表。
    private static final long[] EARLY_GORGON_VALUE_TRACE_ADDRESSES = {
            0x130ed1a0L,
            0x130ed260L,
            0x130ed3e0L
    };
    // 每个早期暂存地址需要监控的长度。
    private static final int EARLY_GORGON_VALUE_TRACE_SIZE = 0x4;
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
    // sub_259154：把 arg2+8 的字符串拷贝到新对象中。
    private static final long METASEC_STRING_COPY_OFFSET = 0x259154L;
    // sub_2590ec 内部，最终 memcpy 前读取 *(arg2 + 0x10) 的位置。
    private static final long METASEC_GORGON_MEMCPY_SRC_OFFSET = 0x259130L;
    // sub_2590ec 内部，真正调用 memcpy 前寄存器已准备好的位置。
    private static final long METASEC_GORGON_MEMCPY_CALL_OFFSET = 0x25913cL;
    // sub_2590ec 内部，从装载 src 到 memcpy 返回前的观测范围结束偏移。
    private static final long METASEC_GORGON_MEMCPY_TRACE_END_OFFSET = 0x259140L;
    // sub_2c6030 内部，调用 sub_2b7724 前 x1/x2 已准备好的位置。
    private static final long METASEC_MAP_INSERT_PRECALL_OFFSET = 0x2c615cL;
    // sub_2c6030 内部，真正调用 sub_2b7724 的位置。
    private static final long METASEC_MAP_INSERT_CALL_OFFSET = 0x2c6160L;
    // sub_257ae0：向字符串尾部追加单个字符。
    private static final long METASEC_GORGON_APPEND_CHAR_OFFSET = 0x257ae0L;
    // sub_2c20d4：自定义封包/RC4-like 变体加密函数入口。
    private static final long METASEC_PACKET_CRYPT_OFFSET = 0x2c20d4L;
    // sub_2c20d4：输出对象已分配、输入仍可直接读取的位置。
    private static final long METASEC_PACKET_CRYPT_AFTER_ALLOC_OFFSET = 0x2c2144L;
    // sub_2c20d4：KSA 即将开始，8 字节 seed 已经落到栈上的位置。
    private static final long METASEC_PACKET_CRYPT_KSA_OFFSET = 0x2c21a8L;
    // sub_2c20d4：包头和密文都已写完、准备返回的位置。
    private static final long METASEC_PACKET_CRYPT_FINAL_OFFSET = 0x2c24d4L;
    // sub_2c269c：第 1 段 4 字节已拼进 sp+0x30 累加器。
    private static final long METASEC_PACKET_INPUT_STAGE1_READY_OFFSET = 0x2c2824L;
    // sub_2c269c：第 2 段 4 字节已拼进 sp+0x30 累加器。
    private static final long METASEC_PACKET_INPUT_STAGE2_READY_OFFSET = 0x2c2838L;
    // sub_2c269c：第 3 段 4 字节已拼进 sp+0x30 累加器。
    private static final long METASEC_PACKET_INPUT_STAGE3_READY_OFFSET = 0x2c284cL;
    // sub_2c269c：第 4 段 4 字节已拼进 sp+0x30 累加器。
    private static final long METASEC_PACKET_INPUT_STAGE4_READY_OFFSET = 0x2c2864L;
    // sub_2c269c：第 5 段 4 字节已拼进 sp+0x30 累加器。
    private static final long METASEC_PACKET_INPUT_STAGE5_READY_OFFSET = 0x2c287cL;
    // sub_2c269c：即将调用 sub_2c20d4，x0 已经指向最终 20 字节输入对象。
    private static final long METASEC_PACKET_INPUT_PRE_CRYPT_CALL_OFFSET = 0x2c28f4L;
    // sub_2c269c：ctx 已取出，stage1/stage2/stage3 的源对象都还能原样观察。
    private static final long METASEC_PACKET_CTX_SNAPSHOT_OFFSET = 0x2c26e4L;
    // sub_2696dc/sub_2696f4：stage1 原始 (ptr,len,flag) 已准备好、即将交给 sub_2694bc。
    private static final long METASEC_STAGE1_RAW_SOURCE_OFFSET = 0x26970cL;
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
    // 记录最近一次 sub_2c20d4 调用的 arg1 地址。
    private long lastSub2c20d4Arg1Peer;
    // 记录最近一次 sub_2c20d4 调用的 arg2。
    private short lastSub2c20d4Arg2;
    // 记录最近一次 sub_2c20d4 调用的 outHolder 地址。
    private long lastSub2c20d4OutHolderPeer;
    // 避免同一轮 KSA 循环重复打印相同 seed。
    private boolean sub2c20d4KsaLogged;

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
        if (ENABLE_GORGON_MEMCPY_SOURCE_HOOK) {
            installGorgonMemcpySourceHook(metasecModule);
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
                        long offset = address - metasecModule.base;
                        if (ENABLE_STRING_COPY_HOOK && ENABLE_LOG_STRING_COPY_DETAILS && offset == METASEC_STRING_COPY_OFFSET) {
                            UnidbgPointer arg1 = emulator.getContext().getPointerArg(0);
                            UnidbgPointer arg2 = emulator.getContext().getPointerArg(1);
                            if (arg2 == null) {
                                System.out.printf("[metasec+0x%x] arg1=%s arg2=null%n", offset, arg1);
                            } else {
                                int len = arg2.getInt(4);
                                Pointer srcPtr = arg2.getPointer(8);
                                UnidbgPointer src = UnidbgPointer.pointer(emulator, UnidbgPointer.nativeValue(srcPtr));
                                System.out.printf("[metasec+0x%x] arg1=%s arg2=%s len=%d *(arg2+8)=%s %s%n",
                                        offset,
                                        arg1,
                                        arg2,
                                        len,
                                        src,
                                        describeSizedBuffer(src, len));
                            }
                        }
                        if (ENABLE_LOG_GORGON_MEMCPY_ARGS && offset == METASEC_GORGON_MEMCPY_SRC_OFFSET) {
                            UnidbgPointer arg2Obj = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X20);
                            if (arg2Obj == null) {
                                System.out.printf("[metasec+0x%x] x20(arg2)=null%n", offset);
                            } else {
                                int len = arg2Obj.getInt(0xc);
                                Pointer srcPtr = arg2Obj.getPointer(0x10);
                                UnidbgPointer src = UnidbgPointer.pointer(emulator, UnidbgPointer.nativeValue(srcPtr));
                                System.out.printf("[metasec+0x%x] x20(arg2)=%s *(arg2+0xc)=%d *(arg2+0x10)=%s %s%n",
                                        offset,
                                        arg2Obj,
                                        len,
                                        src,
                                        describeSizedBuffer(src, len));
                            }
                        }
                        if (ENABLE_LOG_GORGON_MEMCPY_ARGS && offset == METASEC_GORGON_MEMCPY_CALL_OFFSET) {
                            UnidbgPointer src = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                            long len = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X2).longValue();
                            UnidbgPointer arg2Obj = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X20);
                            System.out.printf("[metasec+0x%x] before memcpy x20(arg2)=%s x1(src)=%s x2(len)=%d %s%n",
                                    offset,
                                    arg2Obj,
                                    src,
                                    len,
                                    describeSizedBuffer(src, (int) len));
                        }
                        if (ENABLE_LOG_MAP_INSERT_DETAILS &&
                                (offset == METASEC_MAP_INSERT_PRECALL_OFFSET || offset == METASEC_MAP_INSERT_CALL_OFFSET)) {
                            UnidbgPointer keyObj = emulator.getContext().getPointerArg(1);
                            UnidbgPointer valueObj = emulator.getContext().getPointerArg(2);
                            System.out.printf("[metasec+0x%x] before sub_2b7724 keyObj=%s valueObj=%s%n",
                                    offset, keyObj, valueObj);
                            System.out.println("  key   => " + describeMssdkStringRef(keyObj));
                            System.out.println("  value => " + describeMssdkStringRef(valueObj));
                        }
                        if (ENABLE_SUB_2C20D4_ANALYSIS &&
                                (offset == METASEC_PACKET_CRYPT_OFFSET ||
                                        offset == METASEC_PACKET_CRYPT_AFTER_ALLOC_OFFSET ||
                                        offset == METASEC_PACKET_CRYPT_KSA_OFFSET ||
                                        offset == METASEC_PACKET_CRYPT_FINAL_OFFSET)) {
                            logSub2c20d4AsmTrace(offset, insn.toString());
                        }
                        if (ENABLE_SUB_2C269C_INPUT_BUILD_ANALYSIS &&
                                (offset == METASEC_PACKET_CTX_SNAPSHOT_OFFSET ||
                                        offset == METASEC_PACKET_INPUT_STAGE1_READY_OFFSET ||
                                        offset == METASEC_PACKET_INPUT_STAGE2_READY_OFFSET ||
                                        offset == METASEC_PACKET_INPUT_STAGE3_READY_OFFSET ||
                                        offset == METASEC_PACKET_INPUT_STAGE4_READY_OFFSET ||
                                        offset == METASEC_PACKET_INPUT_STAGE5_READY_OFFSET ||
                                        offset == METASEC_PACKET_INPUT_PRE_CRYPT_CALL_OFFSET)) {
                            logSub2c269cInputBuildTrace(offset, insn.toString());
                        }
                        if (ENABLE_SUB_2C269C_INPUT_BUILD_ANALYSIS &&
                                offset == METASEC_STAGE1_RAW_SOURCE_OFFSET) {
                            logStage1RawSourceTrace(offset, insn.toString());
                        }
                    }
                }
        );
        traceHook.setRedirect(DEV_NULL);
        TraceHook globalValueReadTrace = null;
        TraceHook globalValueWriteTrace = null;
        TraceHook gorgonSourceWriteTrace = null;
        List<TraceHook> earlyGorgonValueWriteTraces = new ArrayList<>();
        final boolean[] gorgonMemcpyArgsPrinted = {false};
        final boolean[] gorgonCharAppendCallstackPrinted = {false};
        if (ENABLE_GLOBAL_VALUE_TRACE) {
            long traceBegin = GLOBAL_VALUE_TRACE_ADDRESS;
            long traceEnd = GLOBAL_VALUE_TRACE_ADDRESS + GLOBAL_VALUE_TRACE_SIZE - 1L;
            System.out.printf("global value trace enabled: [0x%x, 0x%x] size=0x%x%n",
                    traceBegin, traceEnd, GLOBAL_VALUE_TRACE_SIZE);
            if (ENABLE_GLOBAL_VALUE_READ_TRACE) {
                globalValueReadTrace = emulator.traceRead(traceBegin, traceEnd);
            }
            if (ENABLE_GLOBAL_VALUE_WRITE_TRACE) {
                globalValueWriteTrace = emulator.traceWrite(traceBegin, traceEnd, (emu, address, size, value) -> {
                    if (ENABLE_LOG_GORGON_MEMCPY_ARGS && !gorgonMemcpyArgsPrinted[0]) {
                    long lr = emu.getBackend().reg_read(Arm64Const.UC_ARM64_REG_LR).longValue();
                    if (lr == metasecModule.base + 0x259140L) {
                        UnidbgPointer dst = UnidbgPointer.pointer(emu, emu.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X0).longValue());
                        UnidbgPointer src = UnidbgPointer.pointer(emu, emu.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X1).longValue());
                        long len = emu.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X2).longValue();
                        System.out.printf("[gorgon memcpy args] dst=%s src=%s len=%d %s%n",
                                dst,
                                src,
                                len,
                                describeSizedBuffer(src, (int) len));
                        if (ENABLE_LOG_GORGON_SOURCE_CANDIDATES) {
                            printBufferCandidatesAroundSource("  gorgon-src-candidate", src, (int) len);
                        }
                        gorgonMemcpyArgsPrinted[0] = true;
                    }
                }
                return true;
                });
            }
        }
        if (ENABLE_GORGON_SOURCE_BUFFER_TRACE) {
            long traceBegin = GORGON_SOURCE_TRACE_ADDRESS;
            long traceEnd = GORGON_SOURCE_TRACE_ADDRESS + GORGON_SOURCE_TRACE_SIZE - 1L;
            System.out.printf("gorgon source trace enabled: [0x%x, 0x%x] size=0x%x%n",
                    traceBegin, traceEnd, GORGON_SOURCE_TRACE_SIZE);
            gorgonSourceWriteTrace = emulator.traceWrite(traceBegin, traceEnd, (emu, address, size, value) -> {
                if (ENABLE_GORGON_CHAR_APPEND_CALLSTACK &&
                        !gorgonCharAppendCallstackPrinted[0] &&
                        address >= GORGON_SOURCE_TRACE_ADDRESS &&
                        address <= GORGON_SOURCE_TRACE_ADDRESS + GORGON_SOURCE_TRACE_SIZE - 1L) {
                    long pc = emu.getBackend().reg_read(Arm64Const.UC_ARM64_REG_PC).longValue();
                    long offset = pc - metasecModule.base;
                    if (offset >= METASEC_GORGON_APPEND_CHAR_OFFSET && offset < METASEC_GORGON_APPEND_CHAR_OFFSET + 0x80L) {
                        System.out.printf("[gorgon append char] pc=%s write=0x%x size=%d value=0x%x moduleOffset=0x%x%n",
                                emu.getContext().getPCPointer(),
                                address,
                                size,
                                value,
                                offset);
                        dumpNativeCallstack(30);
                        gorgonCharAppendCallstackPrinted[0] = true;
                    }
                }
                return true;
            });
        }
        if (ENABLE_EARLY_GORGON_VALUE_TRACE && EARLY_GORGON_VALUE_TRACE_SIZE > 0) {
            for (long traceBegin : EARLY_GORGON_VALUE_TRACE_ADDRESSES) {
                if (traceBegin == 0) {
                    continue;
                }
                long traceEnd = traceBegin + EARLY_GORGON_VALUE_TRACE_SIZE - 1L;
                System.out.printf("early gorgon value trace enabled: [0x%x, 0x%x] size=0x%x%n",
                        traceBegin, traceEnd, EARLY_GORGON_VALUE_TRACE_SIZE);
                earlyGorgonValueWriteTraces.add(emulator.traceWrite(traceBegin, traceEnd));
            }
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
            for (TraceHook earlyTrace : earlyGorgonValueWriteTraces) {
                earlyTrace.stopTrace();
            }
            if (gorgonSourceWriteTrace != null) {
                gorgonSourceWriteTrace.stopTrace();
            }
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
                if (ENABLE_LOG_COMPONENT_VALUES) {
                    System.out.println("  key   => " + describeMssdkStringRef(keyRef));
                    System.out.println("  value => " + describeMssdkStringRef(valueRef));
                }
                if (ENABLE_LOG_GORGON_CALLSTACK && !gorgonCallstackPrinted && "X-GORGON".equalsIgnoreCase(keyText)) {
                    gorgonCallstackPrinted = true;
                    System.out.println("  X-Gorgon native callstack:");
                    dumpNativeCallstack(30);
                }
            }
        });
        hookZz.disable_arm_arm64_b_branch();
    }

    // 在 bl memcpy 前直接打印 x1/src，确认最终 X-Gorgon 文本源地址。
    private void installGorgonMemcpySourceHook(Module module) {
        long begin = module.base + METASEC_GORGON_MEMCPY_SRC_OFFSET;
        long end = module.base + METASEC_GORGON_MEMCPY_TRACE_END_OFFSET;
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                UnidbgPointer src = UnidbgPointer.pointer(emulator, backend.reg_read(Arm64Const.UC_ARM64_REG_X1).longValue());
                long len = backend.reg_read(Arm64Const.UC_ARM64_REG_X2).longValue();
                UnidbgPointer arg2Obj = UnidbgPointer.pointer(emulator, backend.reg_read(Arm64Const.UC_ARM64_REG_X20).longValue());
                long offset = address - metasecModule.base;
                System.out.printf("[metasec+0x%x] hard-hook x20(arg2)=%s x1(src)=%s x2(len)=%d %s%n",
                        offset,
                        arg2Obj,
                        src,
                        len,
                        describeSizedBuffer(src, (int) len));
            }

            @Override
            public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
            }

            @Override
            public void detach() {
            }
        }, begin, end, emulator);
    }

    // 在 traceCode 命中关键汇编偏移时直接打印寄存器和对象状态。
    private void logSub2c20d4AsmTrace(long offset, String insnText) {
        Backend backend = emulator.getBackend();
        if (offset == METASEC_PACKET_CRYPT_OFFSET) {
            System.out.printf("[metasec+0x%x] sub_2c20d4 asm %s%n", offset, insnText);
            long x0 = reg64(backend, Arm64Const.UC_ARM64_REG_X0);
            long x1 = reg64(backend, Arm64Const.UC_ARM64_REG_X1);
            long x8 = reg64(backend, Arm64Const.UC_ARM64_REG_X8);
            long sp = reg64(backend, Arm64Const.UC_ARM64_REG_SP);
            long fp = reg64(backend, Arm64Const.UC_ARM64_REG_FP);
            lastSub2c20d4Arg1Peer = x0;
            lastSub2c20d4Arg2 = (short) x1;
            lastSub2c20d4OutHolderPeer = x8;
            sub2c20d4KsaLogged = false;
            System.out.printf("  regs  => x0(arg1)=0x%x x1(arg2)=0x%x x8(arg3)=0x%x sp=0x%x fp=0x%x%n",
                    x0, x1, x8, sp, fp);
            logSub2c20d4Input(backend,
                    UnidbgPointer.pointer(emulator, x0),
                    (short) x1,
                    UnidbgPointer.pointer(emulator, x8));
            return;
        }
        if (offset == METASEC_PACKET_CRYPT_AFTER_ALLOC_OFFSET) {
            System.out.printf("[metasec+0x%x] sub_2c20d4 asm %s%n", offset, insnText);
            long x19 = reg64(backend, Arm64Const.UC_ARM64_REG_X19);
            long x20 = reg64(backend, Arm64Const.UC_ARM64_REG_X20);
            long x21 = reg64(backend, Arm64Const.UC_ARM64_REG_X21);
            long x0 = reg64(backend, Arm64Const.UC_ARM64_REG_X0);
            System.out.printf("  regs  => x19(outHolder)=0x%x x20(arg1)=0x%x x21(outRef)=0x%x x0(ret)=0x%x%n",
                    x19, x20, x21, x0);
            logSub2c20d4Input(backend,
                    UnidbgPointer.pointer(emulator, lastSub2c20d4Arg1Peer),
                    lastSub2c20d4Arg2,
                    UnidbgPointer.pointer(emulator, x19));
            return;
        }
        if (offset == METASEC_PACKET_CRYPT_KSA_OFFSET) {
            if (sub2c20d4KsaLogged) {
                return;
            }
            sub2c20d4KsaLogged = true;
            System.out.printf("[metasec+0x%x] sub_2c20d4 asm %s%n", offset, insnText);
            long x19 = reg64(backend, Arm64Const.UC_ARM64_REG_X19);
            long x20 = reg64(backend, Arm64Const.UC_ARM64_REG_X20);
            long x21 = reg64(backend, Arm64Const.UC_ARM64_REG_X21);
            long x22 = reg64(backend, Arm64Const.UC_ARM64_REG_X22);
            long sp = reg64(backend, Arm64Const.UC_ARM64_REG_SP);
            long fp = reg64(backend, Arm64Const.UC_ARM64_REG_FP);
            System.out.printf("  regs  => x19(outHolder)=0x%x x20(keyPtr?)=0x%x x21(keyPtr+4?)=0x%x x22=0x%x sp=0x%x fp=0x%x%n",
                    x19, x20, x21, x22, sp, fp);
            logSub2c20d4KeyMaterial(backend, UnidbgPointer.pointer(emulator, x19));
            return;
        }
        if (offset == METASEC_PACKET_CRYPT_FINAL_OFFSET) {
            System.out.printf("[metasec+0x%x] sub_2c20d4 asm %s%n", offset, insnText);
            long x19 = reg64(backend, Arm64Const.UC_ARM64_REG_X19);
            long x21 = reg64(backend, Arm64Const.UC_ARM64_REG_X21);
            long x24 = reg64(backend, Arm64Const.UC_ARM64_REG_X24);
            System.out.printf("  regs  => x19(outHolder)=0x%x x21(payloadLen)=0x%x x24(outBuf)=0x%x%n",
                    x19, x21, x24);
            logSub2c20d4Output(backend, UnidbgPointer.pointer(emulator, x19), (int) x21);
        }
    }

    // 打印 sub_2c269c 内部 20 字节输入在进入 sub_2c20d4 前的逐段拼装过程。
    private void logSub2c269cInputBuildTrace(long offset, String insnText) {
        Backend backend = emulator.getBackend();
        UnidbgPointer sp = UnidbgPointer.pointer(emulator, reg64(backend, Arm64Const.UC_ARM64_REG_SP));
        UnidbgPointer fp = UnidbgPointer.pointer(emulator, reg64(backend, Arm64Const.UC_ARM64_REG_FP));
        if (offset == METASEC_PACKET_CTX_SNAPSHOT_OFFSET) {
            logSub2c269cContextSnapshot(insnText);
            return;
        }
        if (sp == null) {
            System.out.printf("[metasec+0x%x] sub_2c269c input-build sp=null%n", offset);
            return;
        }

        UnidbgPointer inputRef = UnidbgPointer.pointer(emulator, sp.peer + 0x30L);
        int inputLen = readMssdkStringRefLen(inputRef);
        UnidbgPointer inputBuf = readMssdkStringRefData(inputRef);
        byte[] inputBytes = readBytes(inputBuf, Math.max(inputLen, 0));

        System.out.printf("[metasec+0x%x] sub_2c269c build %s%n", offset, insnText);
        if (offset == METASEC_PACKET_INPUT_STAGE1_READY_OFFSET) {
            UnidbgPointer src1Ref = fp == null ? null : readPointerSlot(fp.peer - 0x30L);
            logSub2c269cInputStage("stage1", inputRef, inputBytes, "src1(first 4)", readMssdkRefPrefixBytes(src1Ref, 4));
            System.out.println("  src1-ref => " + describeMssdkStringRef(src1Ref));
            return;
        }
        if (offset == METASEC_PACKET_INPUT_STAGE2_READY_OFFSET) {
            UnidbgPointer src2Ref = UnidbgPointer.pointer(emulator, reg64(backend, Arm64Const.UC_ARM64_REG_X21));
            logSub2c269cInputStage("stage2", inputRef, inputBytes, "src2(first 4)", readMssdkRefPrefixBytes(src2Ref, 4));
            System.out.println("  src2-ref => " + describeMssdkStringRef(src2Ref));
            return;
        }
        if (offset == METASEC_PACKET_INPUT_STAGE3_READY_OFFSET) {
            UnidbgPointer src3Ref = fp == null ? null : readPointerSlot(fp.peer - 0x40L);
            logSub2c269cInputStage("stage3", inputRef, inputBytes, "src3(first 4)", readMssdkRefPrefixBytes(src3Ref, 4));
            System.out.println("  src3-ref => " + describeMssdkStringRef(src3Ref));
            return;
        }
        if (offset == METASEC_PACKET_INPUT_STAGE4_READY_OFFSET) {
            UnidbgPointer src4 = fp == null ? null : UnidbgPointer.pointer(emulator, fp.peer - 0x44L);
            logSub2c269cInputStage("stage4", inputRef, inputBytes, "src4(sub_181e20 ret)", readBytes(src4, 4));
            if (src4 != null) {
                System.out.printf("  src4-int => 0x%08x%n", src4.getInt(0));
            }
            return;
        }
        if (offset == METASEC_PACKET_INPUT_STAGE5_READY_OFFSET) {
            UnidbgPointer src5 = UnidbgPointer.pointer(emulator, sp.peer + 0x48L);
            logSub2c269cInputStage("stage5", inputRef, inputBytes, "src5(khronos bytes)", readBytes(src5, 4));
            if (src5 != null) {
                System.out.printf("  src5-int => 0x%08x rawCtxField=0x%08x%n", src5.getInt(0), (int) reg64(backend, Arm64Const.UC_ARM64_REG_X20));
            }
            return;
        }

        long x0 = reg64(backend, Arm64Const.UC_ARM64_REG_X0);
        long x1 = reg64(backend, Arm64Const.UC_ARM64_REG_X1);
        long x8 = reg64(backend, Arm64Const.UC_ARM64_REG_X8);
        System.out.printf("  pre-call => x0(inputRef)=0x%x x1(arg2)=0x%x x8(outHolder)=0x%x%n", x0, x1, x8);
        System.out.println("  input-ref => " + describeMssdkStringRef(inputRef));
        System.out.printf("  assembled => %s [%s]%n", Hex.encodeHexString(inputBytes), formatHexChunks(inputBytes, 4));
    }

    // 在 sub_2c269c 刚取出 ctx 时打印关键字段，直接对应 stage1/stage2/stage5 的来源。
    private void logSub2c269cContextSnapshot(String insnText) {
        Backend backend = emulator.getBackend();
        long x21 = reg64(backend, Arm64Const.UC_ARM64_REG_X21);
        long x24 = reg64(backend, Arm64Const.UC_ARM64_REG_X24);
        long x20 = reg64(backend, Arm64Const.UC_ARM64_REG_X20);
        long x22 = reg64(backend, Arm64Const.UC_ARM64_REG_X22);
        UnidbgPointer ctxRef = UnidbgPointer.pointer(emulator, x21);
        UnidbgPointer ctx = UnidbgPointer.pointer(emulator, x24);
        UnidbgPointer stage2Ref = ctx == null ? null : UnidbgPointer.pointer(emulator, ctx.peer + 0x28L);
        UnidbgPointer stage1Obj = ctx == null ? null : UnidbgPointer.pointer(emulator, ctx.peer + 0x40L);
        short arg2 = ctx == null ? 0 : ctx.getShort(0xdc);
        System.out.printf("[metasec+0x%x] sub_2c269c ctx %s%n", METASEC_PACKET_CTX_SNAPSHOT_OFFSET, insnText);
        System.out.printf("  regs  => x21(ctxRef)=0x%x x24(ctx)=0x%x x20(khronosRaw)=0x%x x22(mode)=0x%x%n",
                x21, x24, x20, x22);
        System.out.println("  ctx-ref => " + describeMssdkStringRef(ctxRef));
        System.out.println("  stage2-ref(ctx+0x28) => " + describeMssdkStringRef(stage2Ref));
        System.out.println("  stage1-obj(ctx+0x40) => " + describeSliceObject(stage1Obj));
        System.out.printf("  ctx-fields => mode=%d arg2=0x%04x khronosRaw=0x%08x%n",
                (int) x22,
                arg2 & 0xffff,
                (int) x20);
    }

    // 打印 sub_2c269c 某一轮 4 字节拼接后的累加器状态。
    private void logSub2c269cInputStage(String label, UnidbgPointer inputRef, byte[] assembled, String srcLabel, byte[] srcBytes) {
        System.out.printf("  %s => %s%n", label, describeMssdkStringRef(inputRef));
        System.out.printf("  %s => %s%n", srcLabel, Hex.encodeHexString(srcBytes));
        System.out.printf("  assembled => %s [%s]%n", Hex.encodeHexString(assembled), formatHexChunks(assembled, 4));
    }

    // 打印 stage1 在 sub_2694bc 处理前真正看到的 (ptr,len,flag)。
    private void logStage1RawSourceTrace(long offset, String insnText) {
        Backend backend = emulator.getBackend();
        UnidbgPointer rawPtr = UnidbgPointer.pointer(emulator, reg64(backend, Arm64Const.UC_ARM64_REG_X0));
        int rawLen = (int) reg64(backend, Arm64Const.UC_ARM64_REG_X1);
        int flag = backend.reg_read(Arm64Const.UC_ARM64_REG_X2).intValue();
        byte[] rawBytes = readBytes(rawPtr, Math.max(Math.min(rawLen, 0x20), 0));
        System.out.printf("[metasec+0x%x] sub_2696dc stage1-raw %s%n", offset, insnText);
        System.out.printf("  regs  => x0(rawPtr)=%s x1(rawLen)=0x%x x2(flag)=0x%x%n", rawPtr, rawLen, flag);
        System.out.printf("  raw   => %s%n", describeSizedBuffer(rawPtr, rawLen));
        System.out.printf("  first => %s [%s]%n", Hex.encodeHexString(rawBytes), formatHexChunks(rawBytes, 4));
    }

    // 打印 sub_2c20d4 入口时的输入对象、arg2 和输出对象地址。
    private void logSub2c20d4Input(Backend backend, UnidbgPointer arg1, short arg2, UnidbgPointer outHolder) {
        UnidbgPointer outRef = outHolder == null ? null
                : UnidbgPointer.pointer(emulator, UnidbgPointer.nativeValue(outHolder.getPointer(0)));
        UnidbgPointer outBuf = readMssdkStringRefData(outRef);
        int inputLen = readMssdkStringRefLen(arg1);
        System.out.printf("[metasec+0x%x] sub_2c20d4 input arg1=%s arg2=0x%04x outHolder=%s outRef=%s outBuf=%s%n",
                METASEC_PACKET_CRYPT_OFFSET,
                arg1,
                arg2 & 0xffff,
                outHolder,
                outRef,
                outBuf);
        System.out.println("  input => " + describeMssdkStringRef(arg1));
        if (outRef != null) {
            System.out.println("  out   => " + describeMssdkStringRef(outRef));
        }
        if (inputLen >= 0 && outBuf != null) {
            System.out.printf("  packet layout => header=6 payload=%d total=%d%n", inputLen, inputLen + 6);
        }
    }

    // 打印 sub_2c20d4 在 KSA 前栈上实际使用的 8 字节 seed。
    private void logSub2c20d4KeyMaterial(Backend backend, UnidbgPointer outHolder) {
        UnidbgPointer fp = UnidbgPointer.pointer(emulator, backend.reg_read(Arm64Const.UC_ARM64_REG_FP).longValue());
        UnidbgPointer outRef = outHolder == null ? null
                : UnidbgPointer.pointer(emulator, UnidbgPointer.nativeValue(outHolder.getPointer(0)));
        UnidbgPointer outBuf = readMssdkStringRefData(outRef);
        if (fp == null) {
            System.out.printf("[metasec+0x%x] sub_2c20d4 key material fp=null%n", METASEC_PACKET_CRYPT_KSA_OFFSET);
            return;
        }
        UnidbgPointer keyPtr = UnidbgPointer.pointer(emulator, fp.peer - 0x18L);
        byte[] keyBytes = readBytes(keyPtr, 8);
        short arg2 = readStackShort(0x14);
        long outBufAddr = outBuf == null ? 0 : outBuf.peer;
        System.out.printf("[metasec+0x%x] sub_2c20d4 ksa-seed keyPtr=%s key=%s%n",
                METASEC_PACKET_CRYPT_KSA_OFFSET,
                keyPtr,
                Hex.encodeHexString(keyBytes));
        System.out.printf("  key-bytes => [%s]%n", formatByteList(keyBytes));
        System.out.printf("  key-hint  => arg2=0x%04x outBuf=0x%x low=0x%02x high=0x%02x; 这 8 字节是运行时真正参与 KSA 的 seed%n",
                arg2 & 0xffff,
                outBufAddr,
                outBufAddr & 0xff,
                (outBufAddr >> 8) & 0xff);
    }

    // 打印 sub_2c20d4 返回前的 6 字节包头和密文区。
    private void logSub2c20d4Output(Backend backend, UnidbgPointer outHolder, int payloadLen) {
        UnidbgPointer outRef = outHolder == null ? null
                : UnidbgPointer.pointer(emulator, UnidbgPointer.nativeValue(outHolder.getPointer(0)));
        UnidbgPointer outBuf = readMssdkStringRefData(outRef);
        if (outBuf == null || payloadLen < 0) {
            System.out.printf("[metasec+0x%x] sub_2c20d4 output unavailable outRef=%s outBuf=%s payloadLen=%d%n",
                    METASEC_PACKET_CRYPT_FINAL_OFFSET, outRef, outBuf, payloadLen);
            return;
        }
        int packetLen = payloadLen + 6;
        byte[] packet = readBytes(outBuf, packetLen);
        int headerLen = Math.min(6, packet.length);
        byte[] header = new byte[headerLen];
        System.arraycopy(packet, 0, header, 0, headerLen);
        int cipherLen = Math.max(0, packet.length - 6);
        byte[] cipher = new byte[cipherLen];
        if (cipherLen > 0) {
            System.arraycopy(packet, 6, cipher, 0, cipherLen);
        }
        int arg2 = headerLen >= 6 ? ((header[4] & 0xff) | ((header[5] & 0xff) << 8)) : -1;
        System.out.printf("[metasec+0x%x] sub_2c20d4 output outRef=%s outBuf=%s packetLen=%d%n",
                METASEC_PACKET_CRYPT_FINAL_OFFSET,
                outRef,
                outBuf,
                packetLen);
        System.out.printf("  header => %s [flag0=0x%02x version=0x%02x ptrLo=0x%02x ptrHi=0x%02x arg2=0x%04x]%n",
                Hex.encodeHexString(header),
                headerLen > 0 ? header[0] & 0xff : 0,
                headerLen > 1 ? header[1] & 0xff : 0,
                headerLen > 2 ? header[2] & 0xff : 0,
                headerLen > 3 ? header[3] & 0xff : 0,
                arg2 & 0xffff);
        System.out.printf("  cipher => %s%n", Hex.encodeHexString(cipher));
        System.out.println("  ref    => " + describeMssdkStringRef(outRef));
    }

    // 读取 64 位寄存器值，避免在日志代码里重复样板。
    private long reg64(Backend backend, int regId) {
        return backend.reg_read(regId).longValue();
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
            return String.format("ref=%s alloc=%d len=%d data=%s %s",
                    ref, alloc, len, data, describeSizedBuffer(data, len));
        } catch (Exception e) {
            return "ref=" + ref + " <decode failed: " + e.getMessage() + ">";
        }
    }

    // 格式化 sub_2696dc 使用的 slice/buffer 对象：重点看 len、data 和前几个字节。
    private String describeSliceObject(UnidbgPointer obj) {
        if (obj == null) {
            return "null";
        }
        try {
            int alloc = obj.getInt(8);
            int len = obj.getInt(12);
            Pointer dataPtr = obj.getPointer(16);
            UnidbgPointer data = UnidbgPointer.pointer(emulator, UnidbgPointer.nativeValue(dataPtr));
            byte[] prefix = readBytes(data, Math.max(Math.min(len, 0x20), 0));
            return String.format("obj=%s alloc=%d len=%d data=%s hex=%s",
                    obj,
                    alloc,
                    len,
                    data,
                    Hex.encodeHexString(prefix));
        } catch (Exception e) {
            return obj + " <invalid slice object: " + e.getMessage() + ">";
        }
    }

    // 返回 mssdk 字符串引用的长度，失败时返回 -1。
    private int readMssdkStringRefLen(UnidbgPointer ref) {
        if (ref == null) {
            return -1;
        }
        try {
            return ref.getInt(12);
        } catch (Exception e) {
            return -1;
        }
    }

    // 返回 mssdk 字符串引用的数据指针，失败时返回 null。
    private UnidbgPointer readMssdkStringRefData(UnidbgPointer ref) {
        if (ref == null) {
            return null;
        }
        try {
            Pointer dataPtr = ref.getPointer(16);
            return UnidbgPointer.pointer(emulator, UnidbgPointer.nativeValue(dataPtr));
        } catch (Exception e) {
            return null;
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

    // 按给定长度读取十六进制字符串，便于观察二进制缓冲区。
    private String readSizedHex(UnidbgPointer data, int len) {
        if (data == null) {
            return "null";
        }
        if (len < 0) {
            return "<neg-len:" + len + ">";
        }
        int size = Math.min(len, 0x200);
        byte[] bytes = size == 0 ? new byte[0] : data.getByteArray(0, size);
        return Hex.encodeHexString(bytes);
    }

    // 同时输出缓冲区的十六进制和文本，方便识别内容。
    private String describeSizedBuffer(UnidbgPointer data, int len) {
        return "hex=" + readSizedHex(data, len) + " text=" + readSizedUtf8(data, len);
    }

    // 读取指定长度的原始字节，失败时返回空数组。
    private byte[] readBytes(UnidbgPointer data, int len) {
        if (data == null || len <= 0) {
            return new byte[0];
        }
        try {
            return data.getByteArray(0, len);
        } catch (Exception e) {
            return new byte[0];
        }
    }

    // 读取 mssdk 字符串引用前缀的原始字节。
    private byte[] readMssdkRefPrefixBytes(UnidbgPointer ref, int len) {
        return readBytes(readMssdkStringRefData(ref), len);
    }

    // 把某个栈槽位中保存的指针值读出来并转成 UnidbgPointer。
    private UnidbgPointer readPointerSlot(long address) {
        UnidbgPointer slot = UnidbgPointer.pointer(emulator, address);
        if (slot == null) {
            return null;
        }
        try {
            return UnidbgPointer.pointer(emulator, UnidbgPointer.nativeValue(slot.getPointer(0)));
        } catch (Exception e) {
            return null;
        }
    }

    // 读取当前函数栈上的 16-bit 小端值。
    private short readStackShort(int offset) {
        UnidbgPointer sp = UnidbgPointer.pointer(emulator, emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_SP).longValue());
        return sp == null ? 0 : sp.getShort(offset);
    }

    // 将字节数组格式化成易读的 0x?? 列表。
    private String formatByteList(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder(bytes.length * 6);
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(String.format("0x%02x", bytes[i] & 0xff));
        }
        return sb.toString();
    }

    // 把连续字节按固定宽度切成多段十六进制，方便看 4 字节拼装过程。
    private String formatHexChunks(byte[] bytes, int chunkSize) {
        if (bytes == null || bytes.length == 0 || chunkSize <= 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder(bytes.length * 2 + bytes.length);
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0 && i % chunkSize == 0) {
                sb.append(" | ");
            }
            sb.append(String.format("%02x", bytes[i] & 0xff));
        }
        return sb.toString();
    }

    // 打印 src 附近几个候选起点，便于识别完整字符串真正从哪里开始。
    private void printBufferCandidatesAroundSource(String prefix, UnidbgPointer src, int len) {
        if (src == null) {
            return;
        }
        int[] deltas = { 0x40, 0x30, 0x20, 0x10, 0x00 };
        for (int delta : deltas) {
            long candidateAddr = src.peer - delta;
            UnidbgPointer candidate = UnidbgPointer.pointer(emulator, candidateAddr);
            if (candidate == null) {
                continue;
            }
            System.out.printf("%s start=%s (src-0x%x) %s%n",
                    prefix,
                    candidate,
                    delta,
                    describeSizedBuffer(candidate, len));
        }
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
