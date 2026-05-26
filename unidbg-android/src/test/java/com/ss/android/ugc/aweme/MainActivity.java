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
import org.apache.commons.codec.binary.Hex;
import unicorn.Arm64Const;
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
    // sub_2b7724 的 HookZz.wrap 会把真实入口改写成 trampoline，direct-callback 会卡在这里。
    // 默认关闭这类改写执行流的 hook，保留 caller 侧日志和固定地址 traceWrite。
    private static final boolean ENABLE_COMPONENT_HOOK = false;
    // 是否安装单步调试断点。
    private static final boolean Open_break = false;
    // 手工指定固定毫秒时间戳，设为 null 时走自动推断。
    private static final Long FIXED_TIME_MILLIS = 1779160424642L;
    // 是否从请求参数中自动提取固定时间戳。
    private static final boolean AUTO_FIX_TIME_FROM_REQUEST = true;
    // 是否同步改写 URL 和 header 里的时间字段。
    private static final boolean REWRITE_REQUEST_TIME_FIELDS = true;
    // 是否在执行到 sub_259154 时打印 *(arg2 + 8) 的源字符串。
    private static final boolean ENABLE_STRING_COPY_HOOK = false;
    // 是否在 base64(0x2563b8) 入口打印 arg4 源地址和内容。
    private static final boolean ENABLE_LOG_BASE64_ARG4 = true;
    // 是否打印 memcpy/memmove 调用点的拷贝源。
    private static final boolean ENABLE_LOG_COPY_SOURCES = true;
    // 是否打印组件插入点的 key/value 文本。
    private static final boolean ENABLE_LOG_COMPONENT_VALUES = true;
    // 是否打印 sub_259154 里 *(arg2+8) 的细节。
    private static final boolean ENABLE_LOG_STRING_COPY_DETAILS = false;
    // 是否打印 sub_2b7724 插入前的 key/value 对象。
    private static final boolean ENABLE_LOG_MAP_INSERT_DETAILS = true;
    // 是否从运行时 mapCtx 起始地址开启区域写监控。
    private static final boolean ENABLE_MAP_CTX_TRACE = true;
    // 是否监控当前运行时 X-Helios value 缓冲区的写入。
    private static final boolean ENABLE_HELIOS_VALUE_TRACE = true;
    // 监控 hex-encode 前的 16 字节 raw key32 缓冲区。
    private static final boolean ENABLE_HELIOS_KEY32_RAW16_TRACE = true;
    // 是否向上追踪 X-Helios Base64 生成链路。
    private static final boolean ENABLE_BASE64_UPTRACE = false;
    // 测试 so 和输入文件所在目录。
    private static final File SO_DIR = resolveTestAssetDir();
    // 保存回调 URL 输入文本的文件。
    private static final File CALLBACK_URL_FILE = new File(SO_DIR, "mssdk_callback_url.txt");
    // 保存回调 header 文本的文件。
    private static final File CALLBACK_HEADERS_FILE = new File(SO_DIR, "mssdk_callback_headers.txt");
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
    // base64(arg1, arg2, arg3, arg4, arg5) 入口。
    private static final long METASEC_BASE64_FUNC_OFFSET = 0x2563b8L;
    // sub_2575f4 内部调用 memcpy 前，x1 为源地址，x2 为长度。
    private static final long METASEC_MEMCPY_CALL_OFFSET = 0x2576acL;
    // sub_2578ac 内部调用 memmove 前，x1 为源地址，x2 为长度。
    private static final long METASEC_MEMMOVE_CALL_OFFSET = 0x257994L;
    // 一次性 MD5：arg1=input, arg2=len, arg3=out16。
    private static final long METASEC_MD5_ONESHOT_FUNC_OFFSET = 0x254940L;
    // VM store32：*(slot[dst] + off16) = *(uint32_t*)slot[src]。
    private static final long METASEC_VM_STORE32_OFFSET = 0x2ceac0L;
    // VM slot 更新辅助：会批量把中间值写进 frame->slot[?]。
    private static final long METASEC_VM_SLOT_UPDATE_FUNC_OFFSET = 0x300868L;
    // sub_258f08 内部 memcpy 返回点，此时 prefix4 已经写完。
    private static final long METASEC_REF_COPY_RET_OFFSET = 0x258f64L;
    // 将原始字节编码为十六进制文本的函数入口。
    private static final long METASEC_HEX_ENCODE_FUNC_OFFSET = 0x1a03f4L;
    // direct-callback 失败时封装错误对象的函数入口。
    private static final long METASEC_CALLBACK_ERROR_PACK_FUNC_OFFSET = 0x2a84a0L;
    // direct-callback 分支 1：*x26 == 0，走 -1。
    private static final long METASEC_CALLBACK_FAIL_NEG1_OFFSET = 0x2a889cL;
    // direct-callback 分支 2：x0 == 0，走 -2。
    private static final long METASEC_CALLBACK_FAIL_NEG2_OFFSET = 0x2a88c8L;
    // direct-callback 分支 3：x20[0] == 0 或 sub_26d0e0(x20[0]) == 0，走 -3。
    private static final long METASEC_CALLBACK_FAIL_NEG3_OFFSET = 0x2a88a8L;
    // X-Helios 单块处理函数入口。
    private static final long METASEC_HELIOS_BLOCK_FUNC_OFFSET = 0x2c29a0L;
    // sub_2c269c 内部调用 sub_2c20d4 前，中间输入已经组装完成。
    private static final long METASEC_HELIOS_PREIMAGE_CALL_OFFSET = 0x2c28f4L;
    // 自定义 16 字节混淆/加密函数入口。
    private static final long METASEC_HELIOS_MIX16_FUNC_OFFSET = 0x2c20d4L;
    // sub_2c2b10 内第一次 sub_258f08，固定拷 0x20 字节。
    private static final long METASEC_HELIOS_COPY32_CALL_OFFSET = 0x2c2bdcL;
    // sub_2c2b10 内第二次 sub_258f08，按运行时长度拷贝。
    private static final long METASEC_HELIOS_COPYN_CALL_OFFSET = 0x2c2becL;
    // sub_2c2b10 内最终把计算结果拷到 malloc 输出缓冲区的调用点。
    private static final long METASEC_HELIOS_BODY32_FINALIZE_CALL_OFFSET = 0x2c2cf0L;
    // prefix4 handler：从 frame 的 slot8/9/10 调 sub_258f08。
    private static final long METASEC_HELIOS_PREFIX4_HANDLER_OFFSET = 0x2c2fccL;
    // key32 handler：从 frame 的 slot8/9/10 进入 0x2696dc -> 0x1a03f4 这条 16-byte hex 链。
    private static final long METASEC_HELIOS_KEY32_HANDLER_OFFSET = 0x2c2f7cL;
    // body32 handler：从 frame 的 slot8/9/10 调 sub_2c29a0。
    private static final long METASEC_HELIOS_BODY32_HANDLER_OFFSET = 0x2c3084L;
    // sub_2c29a0 内调用 sub_4b5600 拷贝最终 body32 的位置。
    private static final long METASEC_HELIOS_BODY32_COPY_CALL_OFFSET = 0x2c2ad0L;
    // sub_2c6030 内部，调用 sub_2b7724 前 x1/x2 已准备好的位置。
    private static final long METASEC_MAP_INSERT_PRECALL_OFFSET = 0x2c615cL;
    // sub_2c6030 内部，真正调用 sub_2b7724 的位置。
    private static final long METASEC_MAP_INSERT_CALL_OFFSET = 0x2c6160L;
    // Base64 包装层：x0 是输入对象，x8 是输出 holder。
    private static final long METASEC_BASE64_WRAPPER_OFFSET = 0x269ba4L;
    // 从 batch frame 取 slot8/slot9 后调用 Base64 包装层。
    private static final long METASEC_BASE64_FRAME_CALL_A_OFFSET = 0x2c3120L;
    // 与上面类似的另一条路径。
    private static final long METASEC_BASE64_FRAME_CALL_B_OFFSET = 0x2bf68cL;
    // 上层封装：把 x8 写入 slot8，把 arg1 写入 slot9。
    private static final long METASEC_BASE64_ENTRY_A_OFFSET = 0x2c3974L;
    // 上层封装：另一条入口。
    private static final long METASEC_BASE64_ENTRY_B_OFFSET = 0x2c004cL;
    // 当前运行时 X-Helios value 对应的 data 缓冲区地址。
    private static final long HELIOS_VALUE_TRACE_ADDRESS = 0x13104500L;
    // value 的 alloc=49、len=48，这里把结尾 0 也一起纳入观察。
    private static final int HELIOS_VALUE_TRACE_SIZE = 0x31;
    // 最终送入 base64 的 36 字节二进制缓冲区。
    private static final long HELIOS_BASE64_INPUT_TRACE_ADDRESS = 0x130bf240L;
    // 上面这块缓冲区的实际长度。
    private static final int HELIOS_BASE64_INPUT_TRACE_SIZE = 0x24;
    // X-Helios 前 4 字节拼接源。
    private static final long HELIOS_PREFIX4_TRACE_ADDRESS = 0x12357418L;
    // 前缀长度固定 4 字节。
    private static final int HELIOS_PREFIX4_TRACE_SIZE = 0x4;
    // X-Helios 后 32 字节主体拼接源。
    private static final long HELIOS_BODY32_TRACE_ADDRESS = 0x130bf280L;
    // 主体长度固定 32 字节。
    private static final int HELIOS_BODY32_TRACE_SIZE = 0x20;
    // prefix4 的原始 4 字节中间源。
    private static final long HELIOS_PREFIX4_RAW_TRACE_ADDRESS = 0xe4ff153cL;
    // 上面这块中间源的长度固定 4 字节。
    private static final int HELIOS_PREFIX4_RAW_TRACE_SIZE = 0x4;
    // 为了抓到可能从对齐地址起始的覆盖写，把 prefix4 raw 向前扩 4 字节、总共盯 0x10。
    private static final long HELIOS_PREFIX4_RAW_TRACE_WINDOW_ADDRESS = HELIOS_PREFIX4_RAW_TRACE_ADDRESS - 0x4L;
    // 扩窗后的监控长度。
    private static final int HELIOS_PREFIX4_RAW_TRACE_WINDOW_SIZE = 0x10;
    // body32 拷贝前的 32 字节中间缓冲区。
    private static final long HELIOS_BODY32_RAW_TRACE_ADDRESS = 0x123648c0L;
    // 上面这块中间缓冲区长度固定 32 字节。
    private static final int HELIOS_BODY32_RAW_TRACE_SIZE = 0x20;
    // sub_2c2b10 finalize 前真正的 32 字节输出源。
    private static final long HELIOS_BODY32_FINAL_SRC_TRACE_ADDRESS = 0x12354230L;
    // 上面这块最终源缓冲区长度固定 32 字节。
    private static final int HELIOS_BODY32_FINAL_SRC_TRACE_SIZE = 0x20;
    // hex-encode(0x1a03f4) 前的 16 字节原始 key32 缓冲区。
    private static final long HELIOS_KEY32_RAW16_TRACE_ADDRESS = 0xe4feb3a8L;
    // 上面这块 raw key 缓冲区长度固定 16 字节。
    private static final int HELIOS_KEY32_RAW16_TRACE_SIZE = 0x10;
    // 匹配 URL 中 _rticket 参数的正则。
    private static final Pattern RTICKET_PATTERN = Pattern.compile("([?&])_rticket=(\\d+)");
    // 匹配 URL 中 ts 参数的正则。
    private static final Pattern TS_PATTERN = Pattern.compile("([?&])ts=(\\d+)");

    // 程序入口，构造环境后执行 direct callback 测试。
    public static void main(String[] args) {
        // long start = System.currentTimeMillis();
        MainActivity mainActivity = new MainActivity();
        // System.out.println("load offset=" + (System.currentTimeMillis() - start) + "ms");
        mainActivity.testDirectMetasecCallback();
    }

    // 当前测试使用的 64 位 Android 模拟器。
    private final FixedClockAndroidARM64Emulator emulator;
    // 已加载的 libmetasec_ml.so 模块对象。
    private final Module metasecModule;
    // 手工分配的内存块列表，便于统一持有生命周期。
    private final List<MemoryBlock> manualBlocks = new ArrayList<>();
    // 运行时 mapCtx 区域写监控 hook。
    private TraceHook mapCtxWriteTrace;
    // 当前正在监控的 mapCtx 起始地址。
    private long mapCtxTraceBase;
    // 当前正在监控的 mapCtx 区域长度。
    private int mapCtxTraceSize;

    // 固定地址的安全 traceWrite 配置，不经过 HookZz trampoline。
    private static final class TraceWriteRange {
        private final String label;
        private final long begin;
        private final int size;

        private TraceWriteRange(String label, long begin, int size) {
            this.label = label;
            this.begin = begin;
            this.size = size;
        }
    }

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
        if (ENABLE_BASE64_UPTRACE) {
            installBase64UptraceHooks(metasecModule);
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
                        try {
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
                            if (ENABLE_LOG_BASE64_ARG4 && offset == METASEC_BASE64_FUNC_OFFSET) {
                                UnidbgPointer arg1 = emulator.getContext().getPointerArg(0);
                                long arg2 = emulator.getContext().getLongArg(1);
                                UnidbgPointer arg3 = emulator.getContext().getPointerArg(2);
                                UnidbgPointer arg4 = emulator.getContext().getPointerArg(3);
                                long arg5 = emulator.getContext().getLongArg(4);
                                int previewLen = arg5 <= 0 ? 0 : (int) Math.min(arg5, 0x200L);
                                System.out.printf(
                                        "[metasec+0x%x] base64 arg1(out)=%s arg2(cap)=0x%x arg3(outLenPtr)=%s arg4(src)=%s arg5(len)=%d%n",
                                        offset,
                                        arg1,
                                        arg2,
                                        arg3,
                                        arg4,
                                        arg5
                                );
                                if (arg4 != null) {
                                    System.out.printf("  base64-src-addr=0x%x %s%n",
                                            UnidbgPointer.nativeValue(arg4),
                                            describeSizedBuffer(arg4, previewLen));
                                }
                            }
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_MD5_ONESHOT_FUNC_OFFSET) {
                                UnidbgPointer input = emulator.getContext().getPointerArg(0);
                                int len = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W1).intValue();
                                UnidbgPointer out16 = emulator.getContext().getPointerArg(2);
                                if (out16 != null
                                        && UnidbgPointer.nativeValue(out16) == HELIOS_KEY32_RAW16_TRACE_ADDRESS) {
                                    int previewLen = Math.max(0, Math.min(len, 0x200));
                                    System.out.printf("[metasec+0x%x] md5-oneshot input=%s len=%d out16=%s%n",
                                            offset, input, len, out16);
                                    if (input != null) {
                                        System.out.printf("  md5-input-addr=0x%x %s%n",
                                                UnidbgPointer.nativeValue(input),
                                                describeSizedBuffer(input, previewLen));
                                    }
                                    dumpNativeCallstack(12);
                                }
                            }
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_VM_SLOT_UPDATE_FUNC_OFFSET) {
                                UnidbgPointer arg1 = emulator.getContext().getPointerArg(0);
                                UnidbgPointer arg2 = emulator.getContext().getPointerArg(1);
                                if (arg1 != null && arg2 != null) {
                                    UnidbgPointer slotBase = UnidbgPointer.pointer(emulator, arg2.peer + 0x6070L);
                                    long slot6 = safeReadLong(slotBase, 6L * 8L);
                                    long slot4 = safeReadLong(slotBase, 4L * 8L);
                                    if (slot6 == 0x47563bfaL || slot4 == 0xe4ff1450L) {
                                        System.out.printf("[metasec+0x%x] vm-slot-update arg1=%s frame=%s slotBase=%s slot4=%s slot6=%s%n",
                                                offset,
                                                arg1,
                                                arg2,
                                                slotBase,
                                                formatMaybeHex(slot4),
                                                formatMaybeHex(slot6));
                                        System.out.printf("  arg1[0..7]=%s%n", describeSizedBuffer(arg1, 8));
                                        dumpNativeCallstack(12);
                                    }
                                }
                            }
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_VM_STORE32_OFFSET) {
                                long opValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                                long slotsValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X24).longValue();
                                UnidbgPointer op = UnidbgPointer.pointer(emulator, opValue);
                                UnidbgPointer slots = UnidbgPointer.pointer(emulator, slotsValue);
                                int dstIndex = safeReadU8(op, 0);
                                int srcIndex = safeReadU8(op, 1);
                                int relOff = safeReadS16(op, 2);
                                UnidbgPointer dstBase = safeReadPointer(slots, dstIndex * 8L);
                                UnidbgPointer srcBase = safeReadPointer(slots, srcIndex * 8L);
                                long dstAddr = dstBase == null ? Long.MIN_VALUE : dstBase.peer + relOff;
                                if (dstAddr == HELIOS_PREFIX4_RAW_TRACE_ADDRESS) {
                                    int value = safeReadInt(srcBase, 0);
                                    System.out.printf(
                                            "[metasec+0x%x] vm-store32 dstIndex=%d srcIndex=%d relOff=%d dstBase=%s srcBase=%s dstAddr=0x%x value=0x%x%n",
                                            offset,
                                            dstIndex,
                                            srcIndex,
                                            relOff,
                                            dstBase,
                                            srcBase,
                                            dstAddr,
                                            value
                                    );
                                    if (op != null) {
                                        System.out.printf("  vm-op-addr=0x%x %s%n",
                                                op.peer,
                                                describeSizedBuffer(op, 4));
                                    }
                                    if (srcBase != null) {
                                        System.out.printf("  vm-src-addr=0x%x %s%n",
                                                srcBase.peer,
                                                describeSizedBuffer(srcBase, 0x20));
                                    }
                                    dumpNativeCallstack(16);
                                }
                            }
                            if (ENABLE_LOG_COPY_SOURCES &&
                                    (offset == METASEC_MEMCPY_CALL_OFFSET || offset == METASEC_MEMMOVE_CALL_OFFSET)) {
                                UnidbgPointer dst = emulator.getContext().getPointerArg(0);
                                UnidbgPointer src = emulator.getContext().getPointerArg(1);
                                long len = emulator.getContext().getLongArg(2);
                                int previewLen = len <= 0 ? 0 : (int) Math.min(len, 0x200L);
                                String name = offset == METASEC_MEMCPY_CALL_OFFSET ? "memcpy" : "memmove";
                                System.out.printf("[metasec+0x%x] %s dst=%s src=%s len=%d%n",
                                        offset, name, dst, src, len);
                                if (src != null) {
                                    System.out.printf("  %s-src-addr=0x%x %s%n",
                                            name,
                                            UnidbgPointer.nativeValue(src),
                                            describeSizedBuffer(src, previewLen));
                                }
                            }
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_REF_COPY_RET_OFFSET) {
                                long dstValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X22).longValue();
                                long srcValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X20).longValue();
                                long len = Integer.toUnsignedLong(
                                        emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W19).intValue()
                                );
                                UnidbgPointer dst = UnidbgPointer.pointer(emulator, dstValue);
                                UnidbgPointer src = UnidbgPointer.pointer(emulator, srcValue);
                                if (dst != null
                                        && UnidbgPointer.nativeValue(dst) == HELIOS_PREFIX4_TRACE_ADDRESS
                                        && len == HELIOS_PREFIX4_TRACE_SIZE) {
                                    System.out.printf("[metasec+0x%x] prefix4 write-complete dst=%s src=%s len=%d%n",
                                            offset, dst, src, len);
                                    if (src != null) {
                                        System.out.printf("  prefix4-src-addr=0x%x %s%n",
                                                UnidbgPointer.nativeValue(src),
                                                describeSizedBuffer(src, (int) len));
                                    }
                                    dumpNativeCallstack(20);
                                } else if (len == 26 || len == 32) {
                                    System.out.printf("[metasec+0x%x] object-copy-complete dst=%s src=%s len=%d%n",
                                            offset, dst, src, len);
                                    if (src != null) {
                                        System.out.printf("  object-copy-src-addr=0x%x %s%n",
                                                UnidbgPointer.nativeValue(src),
                                                describeSizedBuffer(src, (int) len));
                                    }
                                    dumpNativeCallstack(16);
                                }
                            }
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_HEX_ENCODE_FUNC_OFFSET) {
                                UnidbgPointer src = emulator.getContext().getPointerArg(0);
                                long len = emulator.getContext().getLongArg(1);
                                long outRefValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X8).longValue();
                                UnidbgPointer outRef = UnidbgPointer.pointer(emulator, outRefValue);
                                if (len == 16 || len == 32) {
                                    int previewLen = (int) Math.min(len, 0x200L);
                                    System.out.printf("[metasec+0x%x] hex-encode src=%s len=%d outRef=%s%n",
                                            offset, src, len, outRef);
                                    if (src != null) {
                                        System.out.printf("  hex-encode-src-addr=0x%x %s%n",
                                                UnidbgPointer.nativeValue(src),
                                                describeSizedBuffer(src, previewLen));
                                    }
                                    dumpNativeCallstack(16);
                                }
                            }
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_CALLBACK_ERROR_PACK_FUNC_OFFSET) {
                                int errorCode = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W0).intValue();
                                long outRefValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X8).longValue();
                                UnidbgPointer outRef = UnidbgPointer.pointer(emulator, outRefValue);
                                System.out.printf("[metasec+0x%x] callback-error-pack code=%d outRef=%s%n",
                                        offset, errorCode, outRef);
                                System.out.println("  outRef => " + describeLenDataObject(outRef));
                                dumpNativeCallstack(12);
                            }
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_CALLBACK_FAIL_NEG1_OFFSET) {
                                long x26Value = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X26).longValue();
                                UnidbgPointer x26 = UnidbgPointer.pointer(emulator, x26Value);
                                long firstQword = safeReadLong(x26, 0);
                                System.out.printf("[metasec+0x%x] callback-fail-branch code=-1 x26=%s [x26]=%s%n",
                                        offset, x26, formatMaybeHex(firstQword));
                            }
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_CALLBACK_FAIL_NEG2_OFFSET) {
                                long x26Value = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X26).longValue();
                                long x0Value = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                                UnidbgPointer x26 = UnidbgPointer.pointer(emulator, x26Value);
                                long firstQword = safeReadLong(x26, 0);
                                System.out.printf("[metasec+0x%x] callback-fail-branch code=-2 x0=0x%x x26=%s [x26]=%s%n",
                                        offset, x0Value, x26, formatMaybeHex(firstQword));
                            }
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_CALLBACK_FAIL_NEG3_OFFSET) {
                                long x20Value = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X20).longValue();
                                long x0Value = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                                UnidbgPointer x20 = UnidbgPointer.pointer(emulator, x20Value);
                                long slot0 = safeReadLong(x20, 0);
                                System.out.printf("[metasec+0x%x] callback-fail-branch code=-3 x0=0x%x x20=%s [x20]=%s%n",
                                        offset, x0Value, x20, formatMaybeHex(slot0));
                            }
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_BASE64_ENTRY_A_OFFSET) {
                                UnidbgPointer arg1 = emulator.getContext().getPointerArg(0);
                                long arg2Value = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X8).longValue();
                                UnidbgPointer arg2 = UnidbgPointer.pointer(emulator, arg2Value);
                                System.out.printf("[metasec+0x%x] sub_2c3974 arg1=%s arg2=%s%n",
                                        offset, arg1, arg2);
                                System.out.println("  arg1 => " + describeLenDataObject(arg1));
                                System.out.println("  arg2 => " + describeLenDataObject(arg2));
                                dumpNativeCallstack(16);
                            }
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_HELIOS_BLOCK_FUNC_OFFSET) {
                                UnidbgPointer arg1 = emulator.getContext().getPointerArg(0);
                                UnidbgPointer arg2 = emulator.getContext().getPointerArg(1);
                                UnidbgPointer arg3 = emulator.getContext().getPointerArg(2);
                                System.out.printf("[metasec+0x%x] sub_2c29a0 arg1=%s arg2=%s arg3=%s%n",
                                        offset, arg1, arg2, arg3);
                                System.out.println("  arg1 => " + describeLenDataObject(arg1));
                                System.out.println("  arg2 => " + describeLenDataObject(arg2));
                                System.out.println("  arg3 => " + describeLenDataObject(arg3));
                            }
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_HELIOS_PREIMAGE_CALL_OFFSET) {
                                UnidbgPointer arg1 = emulator.getContext().getPointerArg(0);
                                int arg2 = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W1).intValue() & 0xffff;
                                long outRefValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X8).longValue();
                                UnidbgPointer outRef = UnidbgPointer.pointer(emulator, outRefValue);
                                System.out.printf("[metasec+0x%x] sub_2c269c -> sub_2c20d4 arg1=%s arg2=0x%x outRef=%s%n",
                                        offset, arg1, arg2, outRef);
                                System.out.println("  preimage => " + describeLenDataObject(arg1));
                            }
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_HELIOS_MIX16_FUNC_OFFSET) {
                                UnidbgPointer arg1 = emulator.getContext().getPointerArg(0);
                                int arg2 = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W1).intValue() & 0xffff;
                                long outRefValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X8).longValue();
                                UnidbgPointer outRef = UnidbgPointer.pointer(emulator, outRefValue);
                                System.out.printf("[metasec+0x%x] sub_2c20d4 arg1=%s arg2=0x%x outRef=%s%n",
                                        offset, arg1, arg2, outRef);
                                System.out.println("  mix16-input => " + describeLenDataObject(arg1));
                            }
                            if (ENABLE_LOG_COPY_SOURCES &&
                                    (offset == METASEC_HELIOS_PREFIX4_HANDLER_OFFSET
                                            || offset == METASEC_HELIOS_KEY32_HANDLER_OFFSET
                                            || offset == METASEC_HELIOS_BODY32_HANDLER_OFFSET)) {
                                UnidbgPointer frame = emulator.getContext().getPointerArg(0);
                                String name;
                                if (offset == METASEC_HELIOS_PREFIX4_HANDLER_OFFSET) {
                                    name = "sub_2c2fcc";
                                } else if (offset == METASEC_HELIOS_KEY32_HANDLER_OFFSET) {
                                    name = "sub_2c2f7c";
                                } else {
                                    name = "sub_2c3084";
                                }
                                System.out.printf("[metasec+0x%x] %s frame=%s%n", offset, name, frame);
                                System.out.println("  slot8  => " + describeBatchFrameSlot(frame, 8));
                                System.out.println("  slot9  => " + describeBatchFrameSlot(frame, 9));
                                System.out.println("  slot10 => " + describeBatchFrameSlot(frame, 10));
                            }
                            if (ENABLE_LOG_COPY_SOURCES &&
                                    (offset == METASEC_HELIOS_COPY32_CALL_OFFSET || offset == METASEC_HELIOS_COPYN_CALL_OFFSET)) {
                                UnidbgPointer dstRef = emulator.getContext().getPointerArg(0);
                                UnidbgPointer src = emulator.getContext().getPointerArg(1);
                                long len = emulator.getContext().getLongArg(2);
                                int previewLen = len <= 0 ? 0 : (int) Math.min(len, 0x200L);
                                String name = offset == METASEC_HELIOS_COPY32_CALL_OFFSET ? "sub_2c2b10 copy32" : "sub_2c2b10 copyN";
                                System.out.printf("[metasec+0x%x] %s dstRef=%s src=%s len=%d%n",
                                        offset, name, dstRef, src, len);
                                if (src != null) {
                                    System.out.printf("  %s-src-addr=0x%x %s%n",
                                            name,
                                            UnidbgPointer.nativeValue(src),
                                            describeSizedBuffer(src, previewLen));
                                }
                            }
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_HELIOS_BODY32_FINALIZE_CALL_OFFSET) {
                                UnidbgPointer dst = emulator.getContext().getPointerArg(0);
                                UnidbgPointer src = emulator.getContext().getPointerArg(1);
                                long len = emulator.getContext().getLongArg(2);
                                if (len == HELIOS_BODY32_TRACE_SIZE) {
                                    System.out.printf("[metasec+0x%x] sub_2c2b10 finalize dst=%s src=%s len=%d%n",
                                            offset, dst, src, len);
                                    if (src != null) {
                                        System.out.printf("  finalize-src-addr=0x%x %s%n",
                                                UnidbgPointer.nativeValue(src),
                                                describeSizedBuffer(src, (int) len));
                                    }
                                    dumpNativeCallstack(16);
                                }
                            }
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_HELIOS_BODY32_COPY_CALL_OFFSET) {
                                UnidbgPointer dst = emulator.getContext().getPointerArg(0);
                                UnidbgPointer src = emulator.getContext().getPointerArg(1);
                                long len = emulator.getContext().getLongArg(2);
                                if (dst != null
                                        && UnidbgPointer.nativeValue(dst) == HELIOS_BODY32_TRACE_ADDRESS
                                        && len == HELIOS_BODY32_TRACE_SIZE) {
                                    System.out.printf("[metasec+0x%x] body32 copy-call dst=%s src=%s len=%d%n",
                                            offset, dst, src, len);
                                    if (src != null) {
                                        System.out.printf("  body32-src-addr=0x%x %s%n",
                                                UnidbgPointer.nativeValue(src),
                                                describeSizedBuffer(src, (int) len));
                                    }
                                    dumpNativeCallstack(20);
                                }
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
                        } catch (Throwable t) {
                            System.out.printf("[metasec+0x%x] trace-log-failed: %s%n",
                                    address - metasecModule.base, t.getMessage());
                        }
                    }
                }
        );
        traceHook.setRedirect(DEV_NULL);
        List<TraceHook> safeTraceWrites = startSafeTraceWrites();

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
            for (TraceHook safeTraceWrite : safeTraceWrites) {
                safeTraceWrite.stopTrace();
            }
            if (mapCtxWriteTrace != null) {
                mapCtxWriteTrace.stopTrace();
                mapCtxWriteTrace = null;
                mapCtxTraceBase = 0;
                mapCtxTraceSize = 0;
            }
            traceHook.stopTrace();
        }
    }

    // 开启不会改写执行流的固定地址 traceWrite。
    private List<TraceHook> startSafeTraceWrites() {
        List<TraceHook> hooks = new ArrayList<>();
        if (ENABLE_HELIOS_VALUE_TRACE) {
            hooks.add(startTraceWriteRange(new TraceWriteRange(
                    "helios value",
                    HELIOS_VALUE_TRACE_ADDRESS,
                    HELIOS_VALUE_TRACE_SIZE
            )));
            hooks.add(startTraceWriteRange(new TraceWriteRange(
                    "helios base64 input",
                    HELIOS_BASE64_INPUT_TRACE_ADDRESS,
                    HELIOS_BASE64_INPUT_TRACE_SIZE
            )));
            hooks.add(startTraceWriteRange(new TraceWriteRange(
                    "helios prefix4 source",
                    HELIOS_PREFIX4_TRACE_ADDRESS,
                    HELIOS_PREFIX4_TRACE_SIZE
            )));
            hooks.add(startTraceWriteRange(new TraceWriteRange(
                    "helios prefix4 raw source",
                    HELIOS_PREFIX4_RAW_TRACE_ADDRESS,
                    HELIOS_PREFIX4_RAW_TRACE_SIZE
            )));
            hooks.add(startTraceWriteRange(new TraceWriteRange(
                    "helios prefix4 raw source window",
                    HELIOS_PREFIX4_RAW_TRACE_WINDOW_ADDRESS,
                    HELIOS_PREFIX4_RAW_TRACE_WINDOW_SIZE
            )));
            hooks.add(startTraceWriteRange(new TraceWriteRange(
                    "helios body32 source",
                    HELIOS_BODY32_TRACE_ADDRESS,
                    HELIOS_BODY32_TRACE_SIZE
            )));
            hooks.add(startTraceWriteRange(new TraceWriteRange(
                    "helios body32 raw source",
                    HELIOS_BODY32_RAW_TRACE_ADDRESS,
                    HELIOS_BODY32_RAW_TRACE_SIZE
            )));
            hooks.add(startTraceWriteRange(new TraceWriteRange(
                    "helios body32 finalize source",
                    HELIOS_BODY32_FINAL_SRC_TRACE_ADDRESS,
                    HELIOS_BODY32_FINAL_SRC_TRACE_SIZE
            )));
            if (ENABLE_HELIOS_KEY32_RAW16_TRACE) {
                hooks.add(startTraceWriteRange(new TraceWriteRange(
                        "helios key32 raw16 source",
                        HELIOS_KEY32_RAW16_TRACE_ADDRESS,
                        HELIOS_KEY32_RAW16_TRACE_SIZE
                )));
            }
        }
        return hooks;
    }

    // 对指定区间开启 traceWrite，并打印可读标签。
    private TraceHook startTraceWriteRange(TraceWriteRange range) {
        long end = range.begin + range.size - 1L;
        System.out.printf("%s trace enabled: [0x%x, 0x%x] size=0x%x%n",
                range.label, range.begin, end, range.size);
        return emulator.traceWrite(range.begin, end);
    }

    // 安装 header 组件插入函数 hook，用于观察插入的 key/value 字段。
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
                ensureMapCtxWriteTrace(mapCtx, valueRef);
                System.out.printf("[metasec+0x%x] lr=%s mapCtx=%s%n", METASEC_COMPONENT_OFFSET, ctx.getLRPointer(), mapCtx);
                if (ENABLE_LOG_COMPONENT_VALUES) {
                    System.out.println("  key   => " + describeMssdkStringRef(keyRef));
                    System.out.println("  value => " + describeMssdkStringRef(valueRef));
                }
            }
        });
        hookZz.disable_arm_arm64_b_branch();
    }

    // 按运行时 mapCtx 地址开启一段连续区域的写监控。
    private void ensureMapCtxWriteTrace(UnidbgPointer mapCtx, UnidbgPointer valueRef) {
        if (!ENABLE_MAP_CTX_TRACE || mapCtx == null) {
            return;
        }
        int traceSize = Math.max(readMssdkStringRefLen(valueRef), 1);
        long base = mapCtx.peer;
        if (mapCtxWriteTrace != null && mapCtxTraceBase == base && mapCtxTraceSize == traceSize) {
            return;
        }
        if (mapCtxWriteTrace != null) {
            mapCtxWriteTrace.stopTrace();
            mapCtxWriteTrace = null;
        }
        long end = base + traceSize - 1L;
        System.out.printf("mapCtx trace enabled: [0x%x, 0x%x] size=0x%x%n", base, end, traceSize);
        mapCtxWriteTrace = emulator.traceWrite(base, end);
        mapCtxTraceBase = base;
        mapCtxTraceSize = traceSize;
    }

    // 安装 X-Helios Base64 生成链的向上溯源 hook。
    private void installBase64UptraceHooks(Module module) {
        IHookZz hookZz = HookZz.getInstance(emulator);
        hookZz.enable_arm_arm64_b_branch();
        wrapBase64EntryHook(hookZz, module.base + METASEC_BASE64_ENTRY_A_OFFSET, "sub_2c3974");
        wrapBase64EntryHook(hookZz, module.base + METASEC_BASE64_ENTRY_B_OFFSET, "sub_2c004c");
        wrapBase64FrameHook(hookZz, module.base + METASEC_BASE64_FRAME_CALL_A_OFFSET, "sub_2c3120");
        wrapBase64FrameHook(hookZz, module.base + METASEC_BASE64_FRAME_CALL_B_OFFSET, "sub_2bf68c");
        wrapBase64WrapperHook(hookZz, module.base + METASEC_BASE64_WRAPPER_OFFSET);
        hookZz.disable_arm_arm64_b_branch();
    }

    // 记录最上层包装入口传入的输入对象和输出 holder。
    private void wrapBase64EntryHook(IHookZz hookZz, long target, String name) {
        hookZz.wrap(target, new WrapCallback<HookZzArm64RegisterContext>() {
            @Override
            public void preCall(Emulator<?> emulator, HookZzArm64RegisterContext ctx, HookEntryInfo info) {
                UnidbgPointer inputObj = ctx.getPointerArg(0);
                UnidbgPointer outHolder = UnidbgPointer.pointer(emulator, ctx.getXLong(8));
                System.out.printf("[metasec+0x%x] %s lr=%s inputObj=%s outHolder=%s%n",
                        target - metasecModule.base, name, ctx.getLRPointer(), inputObj, outHolder);
                System.out.println("  input => " + describeLenDataObject(inputObj));
                System.out.println("  out   => " + describeOutputHolder(outHolder));
            }
        });
    }

    // 记录 batch frame 解包后进入 Base64 wrapper 前的调用现场。
    private void wrapBase64FrameHook(IHookZz hookZz, long target, String name) {
        hookZz.wrap(target, new WrapCallback<HookZzArm64RegisterContext>() {
            @Override
            public void preCall(Emulator<?> emulator, HookZzArm64RegisterContext ctx, HookEntryInfo info) {
                UnidbgPointer frame = ctx.getPointerArg(0);
                System.out.printf("[metasec+0x%x] %s lr=%s frame=%s%n",
                        target - metasecModule.base, name, ctx.getLRPointer(), frame);
            }
        });
    }

    // 记录 Base64 包装层看到的最终输入对象和输出 holder。
    private void wrapBase64WrapperHook(IHookZz hookZz, long target) {
        hookZz.wrap(target, new WrapCallback<HookZzArm64RegisterContext>() {
            @Override
            public void preCall(Emulator<?> emulator, HookZzArm64RegisterContext ctx, HookEntryInfo info) {
                UnidbgPointer inputObj = ctx.getPointerArg(0);
                UnidbgPointer outHolder = UnidbgPointer.pointer(emulator, ctx.getXLong(8));
                System.out.printf("[metasec+0x%x] sub_269ba4 lr=%s inputObj=%s outHolder=%s%n",
                        METASEC_BASE64_WRAPPER_OFFSET, ctx.getLRPointer(), inputObj, outHolder);
                System.out.println("  input => " + describeLenDataObject(inputObj));
                System.out.println("  out   => " + describeOutputHolder(outHolder));
                dumpNativeCallstack(12);
            }
        });
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

    // 按 sub_269c14 使用的布局解析输入对象：len 在 +0xc，data 在 +0x10。
    private String describeLenDataObject(UnidbgPointer obj) {
        if (obj == null) {
            return "null";
        }
        try {
            int len = obj.getInt(0xc);
            Pointer dataPtr = obj.getPointer(0x10);
            UnidbgPointer data = UnidbgPointer.pointer(emulator, UnidbgPointer.nativeValue(dataPtr));
            return String.format("obj=%s len=%d data=%s %s",
                    obj, len, data, describeSizedBuffer(data, len));
        } catch (Exception e) {
            return "obj=" + obj + " <decode failed: " + e.getMessage() + ">";
        }
    }

    // 粗略观察 Base64 输出 holder 的前两个槽位，判断它是谁在接收结果。
    private String describeOutputHolder(UnidbgPointer holder) {
        if (holder == null) {
            return "null";
        }
        try {
            Pointer slot0 = holder.getPointer(0);
            Pointer slot8 = holder.getPointer(8);
            return String.format("holder=%s [0]=0x%x [8]=0x%x",
                    holder,
                    UnidbgPointer.nativeValue(slot0),
                    UnidbgPointer.nativeValue(slot8));
        } catch (Exception e) {
            return "holder=" + holder + " <decode failed: " + e.getMessage() + ">";
        }
    }

    // 读取 BatchFrame 的指定 slot 指针。
    private UnidbgPointer readBatchFrameSlot(UnidbgPointer frame, int slot) {
        if (frame == null) {
            return null;
        }
        try {
            long offset = 0x6070L + slot * 8L;
            Pointer valuePtr = frame.getPointer(offset);
            return UnidbgPointer.pointer(emulator, UnidbgPointer.nativeValue(valuePtr));
        } catch (Exception e) {
            return null;
        }
    }

    // 读取 BatchFrame 的指定 slot 原始 64 位值。
    private long readBatchFrameSlotRawValue(UnidbgPointer frame, int slot) {
        if (frame == null) {
            return 0;
        }
        try {
            long offset = 0x6070L + slot * 8L;
            return frame.getLong(offset);
        } catch (Exception e) {
            return 0;
        }
    }

    // 同时展示 BatchFrame slot 的原始头部和按 len/data 对象解释后的内容。
    private String describeBatchFrameSlot(UnidbgPointer frame, int slot) {
        long rawValue = readBatchFrameSlotRawValue(frame, slot);
        UnidbgPointer value = readBatchFrameSlot(frame, slot);
        if (value == null) {
            return String.format("rawValue=0x%x ptr=null", rawValue);
        }
        return String.format("rawValue=0x%x ptr=%s raw=%s asLenData=%s",
                rawValue,
                value,
                describeSizedBuffer(value, 0x20),
                describeLenDataObject(value));
    }

    // 安全读取 64 位值，失败时返回 Long.MIN_VALUE。
    private long safeReadLong(UnidbgPointer ptr, long offset) {
        if (ptr == null) {
            return Long.MIN_VALUE;
        }
        try {
            return ptr.getLong(offset);
        } catch (Throwable t) {
            return Long.MIN_VALUE;
        }
    }

    // 将可能读取失败的 64 位值格式化为文本。
    private String formatMaybeHex(long value) {
        return value == Long.MIN_VALUE ? "<read-failed>" : String.format("0x%x", value);
    }

    // 安全读取无符号 8 位值，失败时返回 -1。
    private int safeReadU8(UnidbgPointer ptr, long offset) {
        if (ptr == null) {
            return -1;
        }
        try {
            return ptr.getByte(offset) & 0xff;
        } catch (Throwable t) {
            return -1;
        }
    }

    // 安全读取有符号 16 位值，失败时返回 Integer.MIN_VALUE。
    private int safeReadS16(UnidbgPointer ptr, long offset) {
        if (ptr == null) {
            return Integer.MIN_VALUE;
        }
        try {
            return ptr.getShort(offset);
        } catch (Throwable t) {
            return Integer.MIN_VALUE;
        }
    }

    // 安全读取 32 位值，失败时返回 Integer.MIN_VALUE。
    private int safeReadInt(UnidbgPointer ptr, long offset) {
        if (ptr == null) {
            return Integer.MIN_VALUE;
        }
        try {
            return ptr.getInt(offset);
        } catch (Throwable t) {
            return Integer.MIN_VALUE;
        }
    }

    // 安全解引用一个指针槽位，失败时返回 null。
    private UnidbgPointer safeReadPointer(UnidbgPointer ptr, long offset) {
        if (ptr == null) {
            return null;
        }
        try {
            Pointer value = ptr.getPointer(offset);
            return UnidbgPointer.pointer(emulator, UnidbgPointer.nativeValue(value));
        } catch (Throwable t) {
            return null;
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

    // 按给定长度读取 UTF-8 文本并转义换行。
    private String readSizedUtf8(UnidbgPointer data, int len) {
        if (data == null) {
            return "null";
        }
        if (len < 0) {
            return "<neg-len:" + len + ">";
        }
        try {
            int size = Math.min(len, 0x200);
            byte[] bytes = size == 0 ? new byte[0] : data.getByteArray(0, size);
            return new String(bytes, StandardCharsets.UTF_8)
                    .replace("\r", "\\r")
                    .replace("\n", "\\n");
        } catch (Throwable t) {
            return "<utf8-read-failed:" + t.getMessage() + ">";
        }
    }

    // 按给定长度读取十六进制字符串，便于观察二进制缓冲区。
    private String readSizedHex(UnidbgPointer data, int len) {
        if (data == null) {
            return "null";
        }
        if (len < 0) {
            return "<neg-len:" + len + ">";
        }
        try {
            int size = Math.min(len, 0x200);
            byte[] bytes = size == 0 ? new byte[0] : data.getByteArray(0, size);
            return Hex.encodeHexString(bytes);
        } catch (Throwable t) {
            return "<hex-read-failed:" + t.getMessage() + ">";
        }
    }

    // 同时输出缓冲区的十六进制和文本，方便识别内容。
    private String describeSizedBuffer(UnidbgPointer data, int len) {
        return "hex=" + readSizedHex(data, len) + " text=" + readSizedUtf8(data, len);
    }

    // 从磁盘读取整个文本文件。
    private String loadText(File file) {
        try {
            return new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load text file: " + file, e);
        }
    }

    // 兼容从仓库根目录或 unidbg-android 模块目录启动。
    private static File resolveTestAssetDir() {
        File[] candidates = new File[] {
                new File("unidbg-android/src/test/java/com/ss/android/ugc/aweme"),
                new File("src/test/java/com/ss/android/ugc/aweme")
        };
        for (File candidate : candidates) {
            if (new File(candidate, "libmetasec_ml.so").isFile()) {
                return candidate;
            }
        }
        return candidates[0];
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
