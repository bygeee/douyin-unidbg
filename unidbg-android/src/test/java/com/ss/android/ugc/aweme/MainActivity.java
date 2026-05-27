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
import capstone.Arm64_const;
import capstone.api.Instruction;
import capstone.api.OpShift;
import capstone.api.arm64.MemType;
import capstone.api.arm64.OpInfo;
import capstone.api.arm64.Operand;
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
    // 是否打印 direct-callback 失败分支的额外细节。
    private static final boolean ENABLE_LOG_COPY_SOURCES = true;
    // 是否打印组件插入点的 key/value 文本。
    private static final boolean ENABLE_LOG_COMPONENT_VALUES = true;
    // 是否打印 sub_259154 里 *(arg2+8) 的细节。
    private static final boolean ENABLE_LOG_STRING_COPY_DETAILS = false;
    // 是否打印 sub_2b7724 插入前的 key/value 对象。
    private static final boolean ENABLE_LOG_MAP_INSERT_DETAILS = true;
    // 是否从运行时 mapCtx 起始地址开启区域写监控。
    private static final boolean ENABLE_MAP_CTX_TRACE = true;
    // 是否监控当前运行时 X-Ladon value 缓冲区的写入。
    private static final boolean ENABLE_LADON_VALUE_TRACE = true;
    // 是否监控 X-Ladon base64 输入 4 字节缓冲区的写入。
    private static final boolean ENABLE_LADON_ARG4_TRACE = true;
    // 是否监控这次运行里 X-Ladon memcpy 源地址的写入。
    private static final boolean ENABLE_LADON_SRC_TRACE = true;
    // 是否监控 slot[122] 单元的写入。
    private static final boolean ENABLE_LADON_STAGE0_TRACE = true;
    // 是否监控 slot[122] 单元的 system write。
    private static final boolean ENABLE_LADON_STAGE0_SYSTEM_WRITE_TRACE = true;
    // 是否打印命中 slot[122] 的 VM 语义写回，避免只看到原始 traceWrite 噪音。
    private static final boolean ENABLE_LADON_STAGE0_VM_SLOT_LOG = true;
    // 是否监控 slot[5] 单元的 system write。
    private static final boolean ENABLE_LADON_SRC_SYSTEM_WRITE_TRACE = true;
    // 是否监控 slot[6] 单元的写入。
    private static final boolean ENABLE_LADON_SRC_SOURCE_TRACE = true;
    // 是否监控 slot[6] 单元的 system write。
    private static final boolean ENABLE_LADON_SRC_SOURCE_SYSTEM_WRITE_TRACE = true;
    // 是否监控 slot[9] 单元的写入。
    private static final boolean ENABLE_LADON_SLOT9_TRACE = true;
    // 是否监控 slot[9] 单元的 system write。
    private static final boolean ENABLE_LADON_SLOT9_SYSTEM_WRITE_TRACE = true;
    // 是否监控 slot[6] 上游全局 32 位来源地址的写入。
    private static final boolean ENABLE_LADON_GLOBAL_WORD_TRACE = true;
    // 是否监控当前运行时 X-Ladon value 缓冲区的 system write。
    private static final boolean ENABLE_LADON_SYSTEM_WRITE_TRACE = true;
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
    // sub_258f08 内部调用 memcpy 前的现场。
    private static final long METASEC_BUFFER_MEMCPY_PRECALL_OFFSET = 0x258f60L;
    // sub_258f08 内部 memcpy 返回后的现场。
    private static final long METASEC_BUFFER_MEMCPY_POSTCALL_OFFSET = 0x258f64L;
    // VM 指令：x10 已从 slot[src] 载入，但 x12 还没被 opcode selector 覆盖。
    private static final long METASEC_VM_LSL32_TO_SLOT_LOAD_OFFSET = 0x2cf174L;
    // VM 指令：执行 lsl w10, w10, w11 前，x12 已经变成 opcode selector。
    private static final long METASEC_VM_LSL32_TO_SLOT_SHIFT_OFFSET = 0x2cf178L;
    // VM 指令：slot[dst] = signext32(rev16(slot[src]))。
    private static final long METASEC_VM_REV16_TO_SLOT_PRE_OFFSET = 0x2d0f58L;
    // VM 指令：slot[dst] = ror32(slot[src], rot)。
    private static final long METASEC_VM_ROR32_TO_SLOT_PRE_OFFSET = 0x2cea04L;
    // VM 指令：把 slot[src] 的低 32 位写到 slot[dst] + off。
    private static final long METASEC_VM_STORE32_OFFSET = 0x2cead4L;
    // slot[6] 上游：调用 sub_29fb98 前，x0 里还留着 slot[8]。
    private static final long METASEC_LADON_SLOT6_SOURCE_PRECALL_OFFSET = 0x2be454L;
    // slot[6] 上游：sub_29fb98 返回后，w0 就是准备写入 slot[6] 的值。
    private static final long METASEC_LADON_SLOT6_SOURCE_POSTCALL_OFFSET = 0x2be458L;
    // 全局字 setter：调用 sub_291e3c 前，x0=slot[8]，x1=slot[9]。
    private static final long METASEC_LADON_GLOBAL_SET_PRECALL_OFFSET = 0x2be434L;
    // sub_29fb98 返回 sub_4cff50 后，x0 是真实全局字地址，下一条会 ldr w0, [x0]。
    private static final long METASEC_LADON_GLOBAL_WORD_LOAD_OFFSET = 0x29fbacL;
    // 通用 slot copy：在真正 load 源 slot 之前，源/目标 slot 号都还保留在寄存器里。
    private static final long METASEC_VM_COPY_SLOT_PRELOAD_OFFSET = 0x2d0118L;
    // 复合 helper 的第二段 slot copy：在 load 源 slot 前记录 src/dst。
    private static final long METASEC_VM_COPY_SLOT2_PRELOAD_OFFSET = 0x2d70b8L;
    // 复合 helper 的第三段 slot copy：在 load 源 slot 前记录 src/dst。
    private static final long METASEC_VM_COPY_SLOT3_PRELOAD_OFFSET = 0x2d7104L;
    // add 类 handler：在真正解引用源指针前，dst slot、源指针和 addend 都还可见。
    private static final long METASEC_VM_ADD_PTR_IMM_TO_SLOT_PRELOAD_OFFSET = 0x2d1ba4L;
    // xor64 类 handler：在真正 load 源 slot 前，srcA/srcB/dst 三个 slot 号都已就位。
    private static final long METASEC_VM_XOR64_TO_SLOT_PRELOAD_OFFSET = 0x2d15e8L;
    // 通用 VM 槽位写 helper：arg1->slots[arg2] = arg3。
    private static final long METASEC_VM_WRITE_SLOT_HELPER_OFFSET = 0x2cb884L;
    // VM handler 大致落在这段代码区，语义写回只在这里做 operand 级过滤。
    private static final long METASEC_VM_SLOT_WRITE_SCAN_BEGIN = 0x2ce000L;
    private static final long METASEC_VM_SLOT_WRITE_SCAN_END = 0x310000L;
    // X-Ladon 路径里真正调用 base64 前的现场。
    private static final long METASEC_LADON_BASE64_CALL_OFFSET = 0x269dd8L;
    // direct-callback 失败时封装错误对象的函数入口。
    private static final long METASEC_CALLBACK_ERROR_PACK_FUNC_OFFSET = 0x2a84a0L;
    // direct-callback 分支 1：*x26 == 0，走 -1。
    private static final long METASEC_CALLBACK_FAIL_NEG1_OFFSET = 0x2a889cL;
    // direct-callback 分支 2：x0 == 0，走 -2。
    private static final long METASEC_CALLBACK_FAIL_NEG2_OFFSET = 0x2a88c8L;
    // direct-callback 分支 3：x20[0] == 0 或 sub_26d0e0(x20[0]) == 0，走 -3。
    private static final long METASEC_CALLBACK_FAIL_NEG3_OFFSET = 0x2a88a8L;
    // sub_2c6030 内部，调用 sub_2b7724 前 x1/x2 已准备好的位置。
    private static final long METASEC_MAP_INSERT_PRECALL_OFFSET = 0x2c615cL;
    // sub_2c6030 内部，真正调用 sub_2b7724 的位置。
    private static final long METASEC_MAP_INSERT_CALL_OFFSET = 0x2c6160L;
    // 运行时观测到的 X-Ladon value 数据地址。
    private static final long LADON_VALUE_TRACE_ADDRESS = 0x123585b0L;
    // 当前样本中 X-Ladon value 的长度为 8。
    private static final int LADON_VALUE_TRACE_SIZE = 0x8;
    // X-Ladon base64 输入 arg4 的运行时数据地址。
    private static final long LADON_ARG4_TRACE_ADDRESS = 0x12357410L;
    // 当前样本中 arg4 为 4 字节。
    private static final int LADON_ARG4_TRACE_SIZE = 0x4;
    // VM store32 最终把值写入的源缓冲区地址。
    private static final long LADON_VM_STORE_DST_ADDRESS = 0xe4ff7998L;
    // 这次运行中 slot[122] 单元地址。
    private static final long LADON_STAGE0_TRACE_ADDRESS = 0xe4ff7f60L;
    // slot[122] 单元占 8 字节。
    private static final int LADON_STAGE0_TRACE_SIZE = 0x8;
    // stage0 上游可能通过相邻 slot 的宽写覆盖进来，固定地址 trace 向前后各放宽一小段。
    private static final int LADON_STAGE0_TRACE_PAD = 0x20;
    // X-Ladon 上游中间值的语义槽号。
    private static final int LADON_STAGE0_SLOT_INDEX = 122;
    // 这次运行中 slot[5] 单元地址。
    private static final long LADON_SRC_TRACE_ADDRESS = 0xe4ff7bb8L;
    // slot[5] 单元占 8 字节。
    private static final int LADON_SRC_TRACE_SIZE = 0x8;
    // 当前样本里 X-Ladon 的 VM 中间值落在 slot[5]。
    private static final int LADON_VM_RESULT_SLOT = 5;
    // 这次运行中 slot[6] 单元地址，是 Ladon 变换前的真实源槽位。
    private static final long LADON_SRC_SOURCE_TRACE_ADDRESS = 0xe4ff7bc0L;
    // slot[6] 单元占 8 字节。
    private static final int LADON_SRC_SOURCE_TRACE_SIZE = 0x8;
    // 当前样本里 X-Ladon 变换前的真实源槽号。
    private static final int LADON_VM_SOURCE_SLOT = 6;
    // slot[9] 是写入全局字前的直接来源槽。
    private static final long LADON_SLOT9_TRACE_ADDRESS = 0xe4ff7bd8L;
    private static final int LADON_SLOT9_TRACE_SIZE = 0x8;
    private static final int LADON_VM_GLOBAL_SOURCE_SLOT = 9;
    // slot[6] 上游全局字只读取 4 字节。
    private static final int LADON_GLOBAL_WORD_TRACE_SIZE = 0x4;
    // VM 槽位按 8 字节对齐排列。
    private static final int METASEC_VM_SLOT_STRIDE = 0x8;
    // 为了抓对齐写，固定向前后各扩 0x20。
    private static final int LADON_VALUE_TRACE_PAD = 0x20;
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
    // 固定地址的 X-Ladon value 写监控 hook。
    private TraceHook ladonValueWriteTrace;
    // 固定地址的 X-Ladon arg4 写监控 hook。
    private TraceHook ladonArg4WriteTrace;
    // 固定地址的 slot[122] 写监控 hook。
    private TraceHook ladonStage0WriteTrace;
    // 固定地址的 X-Ladon memcpy 源写监控 hook。
    private TraceHook ladonSrcWriteTrace;
    // 固定地址的 X-Ladon 真实源槽 slot[6] 写监控 hook。
    private TraceHook ladonSrcSourceWriteTrace;
    // 固定地址的 slot[9] 写监控 hook。
    private TraceHook ladonSlot9WriteTrace;
    // 动态解析出的 slot[6] 上游全局字写监控 hook。
    private TraceHook ladonGlobalWordWriteTrace;
    // 当前正在监控的 mapCtx 起始地址。
    private long mapCtxTraceBase;
    // 当前正在监控的 mapCtx 区域长度。
    private int mapCtxTraceSize;
    // 当前正在监控的 slot[6] 上游全局字地址。
    private long ladonGlobalWordTraceBase;

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
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_BUFFER_MEMCPY_PRECALL_OFFSET) {
                                UnidbgPointer dst = emulator.getContext().getPointerArg(0);
                                UnidbgPointer src = emulator.getContext().getPointerArg(1);
                                int len = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W2).intValue();
                                long objValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X21).longValue();
                                UnidbgPointer obj = UnidbgPointer.pointer(emulator, objValue);
                                int previewLen = Math.max(len, 0);
                                System.out.printf("[metasec+0x%x] sub_258f08 memcpy-pre dst=%s src=%s len=%d obj=%s%n",
                                        offset, dst, src, len, obj);
                                if (src != null) {
                                    System.out.println("  src => " + describeSizedBuffer(src, previewLen));
                                }
                                if (dst != null) {
                                    System.out.println("  dst(before) => " + describeSizedBuffer(dst, previewLen));
                                }
                                if (obj != null) {
                                    System.out.println("  obj => " + describeLenDataObject(obj));
                                }
                            }
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_BUFFER_MEMCPY_POSTCALL_OFFSET) {
                                long dstValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X22).longValue();
                                long srcValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X20).longValue();
                                int len = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W19).intValue();
                                UnidbgPointer dst = UnidbgPointer.pointer(emulator, dstValue);
                                UnidbgPointer src = UnidbgPointer.pointer(emulator, srcValue);
                                System.out.printf("[metasec+0x%x] sub_258f08 memcpy-post dst=%s src=%s len=%d%n",
                                        offset, dst, src, len);
                                if (dst != null) {
                                    System.out.println("  dst(after) => " + describeSizedBuffer(dst, len));
                                }
                                if (src != null) {
                                    System.out.println("  src => " + describeSizedBuffer(src, len));
                                }
                            }
                            maybeLogStage0VmSlotWrite(emulator, offset, insn);
                            maybeLogLadonSlot9VmWrite(emulator, offset, insn);
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_VM_WRITE_SLOT_HELPER_OFFSET) {
                                long ctxValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                                int slot = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W1).intValue();
                                long value = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X2).longValue();
                                long lrValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X30).longValue();
                                long dstCell = ctxValue + 0x6070L + (long) slot * METASEC_VM_SLOT_STRIDE;
                                if (slot == LADON_STAGE0_SLOT_INDEX ||
                                        slot == LADON_VM_SOURCE_SLOT ||
                                        slot == LADON_VM_GLOBAL_SOURCE_SLOT ||
                                        dstCell == LADON_STAGE0_TRACE_ADDRESS ||
                                        dstCell == LADON_SRC_SOURCE_TRACE_ADDRESS ||
                                        dstCell == LADON_SLOT9_TRACE_ADDRESS) {
                                    String caller = (lrValue >= metasecModule.base && lrValue < metasecModule.base + metasecModule.size)
                                            ? String.format("RX@0x%x[libmetasec_ml.so]0x%x", lrValue, lrValue - metasecModule.base)
                                            : String.format("0x%x", lrValue);
                                    UnidbgPointer dstPtr = UnidbgPointer.pointer(emulator, dstCell);
                                    System.out.printf("[metasec+0x%x] vm-write-slot-helper ctx=0x%x slot=%d dstCell=0x%x value=0x%x lr=%s%n",
                                            offset,
                                            ctxValue,
                                            slot,
                                            dstCell,
                                            value,
                                            caller);
                                    if (dstPtr != null) {
                                        System.out.println("  dst(before) => " + describeSizedBuffer(dstPtr, METASEC_VM_SLOT_STRIDE));
                                    }
                                }
                            }
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_LADON_SLOT6_SOURCE_PRECALL_OFFSET) {
                                long ctxValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X19).longValue();
                                long slot8Value = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                                System.out.printf("[metasec+0x%x] ladon-slot6-precall ctx=0x%x slot8Value=0x%x call=sub_29fb98%n",
                                        offset, ctxValue, slot8Value);
                            }
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_LADON_GLOBAL_SET_PRECALL_OFFSET) {
                                long ctxValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X19).longValue();
                                long slot8Value = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                                long slot9Value = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X1).longValue();
                                System.out.printf("[metasec+0x%x] ladon-global-set-precall ctx=0x%x slot8Value=0x%x slot9Value=0x%x call=sub_291e3c%n",
                                        offset, ctxValue, slot8Value, slot9Value);
                            }
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_LADON_SLOT6_SOURCE_POSTCALL_OFFSET) {
                                long ctxValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X19).longValue();
                                long retValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                                System.out.printf("[metasec+0x%x] ladon-slot6-postcall ctx=0x%x ret32=0x%x%n",
                                        offset, ctxValue, retValue & 0xffffffffL);
                            }
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_LADON_GLOBAL_WORD_LOAD_OFFSET) {
                                long globalPtrValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                                UnidbgPointer globalPtr = UnidbgPointer.pointer(emulator, globalPtrValue);
                                ensureLadonGlobalWordWriteTrace(globalPtr);
                                long raw32 = safeReadInt(globalPtr, 0) & 0xffffffffL;
                                System.out.printf("[metasec+0x%x] ladon-global-word-load ptr=%s raw32=0x%x%n",
                                        offset, globalPtr, raw32);
                            }
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_VM_COPY_SLOT_PRELOAD_OFFSET) {
                                int srcSlot = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W9).intValue();
                                int dstSlot = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W11).intValue();
                                logLadonSlotCopyPreload(emulator, offset, "vm-copy-slot", srcSlot, dstSlot);
                            }
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_VM_COPY_SLOT2_PRELOAD_OFFSET) {
                                int srcSlot = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W9).intValue();
                                int dstSlot = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W10).intValue();
                                logLadonSlotCopyPreload(emulator, offset, "vm-copy-slot2", srcSlot, dstSlot);
                            }
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_VM_COPY_SLOT3_PRELOAD_OFFSET) {
                                int srcSlot = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W10).intValue();
                                int dstSlot = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W9).intValue();
                                logLadonSlotCopyPreload(emulator, offset, "vm-copy-slot3", srcSlot, dstSlot);
                            }
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_VM_ADD_PTR_IMM_TO_SLOT_PRELOAD_OFFSET) {
                                int dstSlot = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W13).intValue();
                                if (dstSlot == LADON_VM_GLOBAL_SOURCE_SLOT) {
                                    long srcHolderValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X10).longValue();
                                    long addend = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X11).longValue();
                                    long slotBaseValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X24).longValue();
                                    UnidbgPointer slotBase = UnidbgPointer.pointer(emulator, slotBaseValue);
                                    UnidbgPointer srcHolder = UnidbgPointer.pointer(emulator, srcHolderValue);
                                    long loaded = srcHolder == null ? 0L : srcHolder.getLong(0);
                                    long result = loaded + addend;
                                    System.out.printf("[metasec+0x%x] vm-add-ptr-imm-to-slot dstSlot=%d slotBase=%s srcHolder=%s loaded=0x%x addend=0x%x result=0x%x dstCell=0x%x%n",
                                            offset,
                                            dstSlot,
                                            slotBase,
                                            srcHolder,
                                            loaded,
                                            addend,
                                            result,
                                            LADON_SLOT9_TRACE_ADDRESS);
                                    if (srcHolder != null) {
                                        System.out.println("  srcHolder => " + describeSizedBuffer(srcHolder, 8));
                                    }
                                }
                            }
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_VM_XOR64_TO_SLOT_PRELOAD_OFFSET) {
                                int srcSlotA = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W9).intValue();
                                int srcSlotB = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W10).intValue();
                                int dstSlot = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W12).intValue();
                                if (dstSlot == LADON_VM_SOURCE_SLOT || dstSlot == LADON_VM_GLOBAL_SOURCE_SLOT) {
                                    long slotBaseValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X24).longValue();
                                    UnidbgPointer slotBase = UnidbgPointer.pointer(emulator, slotBaseValue);
                                    long srcValueA = slotBase == null ? 0L : slotBase.getLong((long) srcSlotA * METASEC_VM_SLOT_STRIDE);
                                    long srcValueB = slotBase == null ? 0L : slotBase.getLong((long) srcSlotB * METASEC_VM_SLOT_STRIDE);
                                    long result = srcValueA ^ srcValueB;
                                    System.out.printf("[metasec+0x%x] vm-xor64-to-slot slotBase=%s srcSlotA=%d srcValueA=0x%x srcSlotB=%d srcValueB=0x%x dstSlot=%d result=0x%x dstCell=0x%x%n",
                                            offset,
                                            slotBase,
                                            srcSlotA,
                                            srcValueA,
                                            srcSlotB,
                                            srcValueB,
                                            dstSlot,
                                            result,
                                            slotBaseValue + (long) dstSlot * METASEC_VM_SLOT_STRIDE);
                                }
                            }
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_VM_LSL32_TO_SLOT_LOAD_OFFSET) {
                                int srcSlot = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W12).intValue();
                                int dstSlot = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W9).intValue();
                                int shift = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W11).intValue() & 31;
                                long srcRaw = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X10).longValue();
                                long slotBaseValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X24).longValue();
                                UnidbgPointer slotBase = UnidbgPointer.pointer(emulator, slotBaseValue);
                                long dstCell = slotBaseValue + (long) dstSlot * 8L;
                                long srcCell = slotBaseValue + (long) srcSlot * 8L;
                                if (dstSlot == LADON_VM_RESULT_SLOT && dstCell == LADON_SRC_TRACE_ADDRESS) {
                                    long slotMemRaw = slotBase == null ? 0L : slotBase.getLong((long) srcSlot * 8L);
                                    int src32 = (int) srcRaw;
                                    int result32 = src32 << shift;
                                    System.out.printf("[metasec+0x%x] vm-lsl32-load slotBase=%s srcSlot=%d srcCell=0x%x slotMemRaw=0x%x x10Loaded=0x%x dstSlot=%d shift=%d src32=0x%x result32=0x%x dstCell=0x%x%n",
                                            offset,
                                            slotBase,
                                            srcSlot,
                                            srcCell,
                                            slotMemRaw,
                                            srcRaw,
                                            dstSlot,
                                            shift,
                                            src32,
                                            result32,
                                            dstCell);
                                }
                            }
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_VM_LSL32_TO_SLOT_SHIFT_OFFSET) {
                                int dstSlot = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W9).intValue();
                                int shift = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W11).intValue() & 31;
                                long slotBaseValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X24).longValue();
                                long dstCell = slotBaseValue + (long) dstSlot * 8L;
                                if (dstSlot == LADON_VM_RESULT_SLOT && dstCell == LADON_SRC_TRACE_ADDRESS) {
                                    long opcodeSelector = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X12).longValue();
                                    long srcRaw = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X10).longValue();
                                    int src32 = (int) srcRaw;
                                    int result32 = src32 << shift;
                                    System.out.printf("[metasec+0x%x] vm-lsl32-shift opcodeSel=0x%x dstSlot=%d shift=%d srcRaw=0x%x src32=0x%x result32=0x%x dstCell=0x%x%n",
                                            offset,
                                            opcodeSelector,
                                            dstSlot,
                                            shift,
                                            srcRaw,
                                            src32,
                                            result32,
                                            dstCell);
                                }
                            }
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_VM_REV16_TO_SLOT_PRE_OFFSET) {
                                int srcSlot = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W9).intValue();
                                int dstSlot = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W10).intValue();
                                long slotBaseValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X24).longValue();
                                UnidbgPointer slotBase = UnidbgPointer.pointer(emulator, slotBaseValue);
                                long dstCell = slotBaseValue + (long) dstSlot * 8L;
                                if (dstSlot == LADON_VM_RESULT_SLOT && dstCell == LADON_SRC_TRACE_ADDRESS && slotBase != null) {
                                    long srcRaw = slotBase.getLong((long) srcSlot * 8L);
                                    int src32 = (int) srcRaw;
                                    int result32 = Integer.reverseBytes(src32) >>> 16 | (Integer.reverseBytes(src32) << 16);
                                    result32 = (((src32 & 0x00ff00ff) << 8) | ((src32 & 0xff00ff00) >>> 8));
                                    System.out.printf("[metasec+0x%x] vm-rev16-to-slot slotBase=%s srcSlot=%d dstSlot=%d srcRaw=0x%x src32=0x%x result32=0x%x dstCell=0x%x%n",
                                            offset,
                                            slotBase,
                                            srcSlot,
                                            dstSlot,
                                            srcRaw,
                                            src32,
                                            result32,
                                            dstCell);
                                }
                            }
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_VM_ROR32_TO_SLOT_PRE_OFFSET) {
                                int srcSlot = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W8).intValue();
                                int dstSlot = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W10).intValue();
                                int rot = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W12).intValue() & 31;
                                long slotBaseValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X24).longValue();
                                UnidbgPointer slotBase = UnidbgPointer.pointer(emulator, slotBaseValue);
                                long dstCell = slotBaseValue + (long) dstSlot * 8L;
                                if (dstSlot == LADON_VM_RESULT_SLOT && dstCell == LADON_SRC_TRACE_ADDRESS && slotBase != null) {
                                    long srcRaw = slotBase.getLong((long) srcSlot * 8L);
                                    int src32 = (int) srcRaw;
                                    int result32 = Integer.rotateRight(src32, rot);
                                    System.out.printf("[metasec+0x%x] vm-ror32-to-slot slotBase=%s srcSlot=%d dstSlot=%d rot=%d srcRaw=0x%x src32=0x%x result32=0x%x dstCell=0x%x%n",
                                            offset,
                                            slotBase,
                                            srcSlot,
                                            dstSlot,
                                            rot,
                                            srcRaw,
                                            src32,
                                            result32,
                                            dstCell);
                                }
                            }
                            if (ENABLE_LOG_COPY_SOURCES && offset == METASEC_VM_STORE32_OFFSET) {
                                long dstBase = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X8).longValue();
                                long srcValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X9).longValue();
                                long offValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X10).longValue();
                                long insnPtrValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                                long slotBaseValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X24).longValue();
                                UnidbgPointer insnPtr = UnidbgPointer.pointer(emulator, insnPtrValue);
                                long dstAddress = dstBase + offValue;
                                if (dstAddress == LADON_VM_STORE_DST_ADDRESS && insnPtr != null) {
                                    int dstSlot = Byte.toUnsignedInt(insnPtr.getByte(0));
                                    int srcSlot = Byte.toUnsignedInt(insnPtr.getByte(1));
                                    short dstOff = insnPtr.getShort(2);
                                    UnidbgPointer slotBase = UnidbgPointer.pointer(emulator, slotBaseValue);
                                    System.out.printf("[metasec+0x%x] vm-store32 insn=%s slotBase=%s dstSlot=%d srcSlot=%d off=%d dstBase=0x%x dst=0x%x srcVal=0x%x%n",
                                            offset,
                                            insnPtr,
                                            slotBase,
                                            dstSlot,
                                            srcSlot,
                                            (int) dstOff,
                                            dstBase,
                                            dstAddress,
                                            srcValue);
                                    System.out.println("  opcode => " + describeSizedBuffer(insnPtr, 4));
                                    if (slotBase != null) {
                                        UnidbgPointer dstSlotPtr = slotBase.getPointer((long) dstSlot * 8L);
                                        UnidbgPointer srcSlotPtr = slotBase.getPointer((long) srcSlot * 8L);
                                        System.out.printf("  slot[%d] => %s%n", dstSlot, dstSlotPtr);
                                        System.out.printf("  slot[%d] => %s%n", srcSlot, srcSlotPtr);
                                    }
                                }
                            }
                            if (offset == METASEC_LADON_BASE64_CALL_OFFSET) {
                                UnidbgPointer out = emulator.getContext().getPointerArg(0);
                                long outCap = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X1).longValue();
                                UnidbgPointer outLenPtr = emulator.getContext().getPointerArg(2);
                                UnidbgPointer arg4 = emulator.getContext().getPointerArg(3);
                                long arg5 = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X4).longValue();
                                long srcObjValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X19).longValue();
                                UnidbgPointer srcObj = UnidbgPointer.pointer(emulator, srcObjValue);
                                int previewLen = arg5 <= 0 ? 0 : (int) Math.min(arg5, 0x200L);
                                System.out.printf("[metasec+0x%x] sub_269dc8 -> base64 out=%s cap=0x%x outLenPtr=%s arg4(src)=%s arg5(len)=%d srcObj=%s%n",
                                        offset, out, outCap, outLenPtr, arg4, arg5, srcObj);
                                System.out.println("  srcObj => " + describeLenDataObject(srcObj));
                                if (arg4 != null) {
                                    System.out.printf("  arg4-addr=0x%x %s%n",
                                            UnidbgPointer.nativeValue(arg4),
                                            describeSizedBuffer(arg4, previewLen));
                                }
                            }
                            if (ENABLE_LOG_COMPONENT_VALUES && offset == METASEC_COMPONENT_OFFSET) {
                                UnidbgPointer mapCtx = emulator.getContext().getPointerArg(0);
                                UnidbgPointer keyRef = emulator.getContext().getPointerArg(1);
                                UnidbgPointer valueRef = emulator.getContext().getPointerArg(2);
                                ensureMapCtxWriteTrace(mapCtx, valueRef);
                                System.out.printf("[metasec+0x%x] lr=%s mapCtx=%s%n",
                                        offset,
                                        emulator.getContext().getLRPointer(),
                                        mapCtx);
                                System.out.println("  key   => " + describeMssdkStringRef(keyRef));
                                System.out.println("  value => " + describeMssdkStringRef(valueRef));
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
        if (ENABLE_LADON_VALUE_TRACE) {
            long begin = LADON_VALUE_TRACE_ADDRESS - LADON_VALUE_TRACE_PAD;
            long end = LADON_VALUE_TRACE_ADDRESS + LADON_VALUE_TRACE_SIZE + LADON_VALUE_TRACE_PAD - 1L;
            System.out.printf("ladon value trace enabled: [0x%x, 0x%x] focus=[0x%x, 0x%x] size=0x%x%n",
                    begin, end,
                    LADON_VALUE_TRACE_ADDRESS,
                    LADON_VALUE_TRACE_ADDRESS + LADON_VALUE_TRACE_SIZE - 1L,
                    LADON_VALUE_TRACE_SIZE);
            ladonValueWriteTrace = emulator.traceWrite(begin, end);
        }
        if (ENABLE_LADON_ARG4_TRACE) {
            long begin = LADON_ARG4_TRACE_ADDRESS;
            long end = LADON_ARG4_TRACE_ADDRESS + LADON_ARG4_TRACE_SIZE - 1L;
            System.out.printf("ladon arg4 trace enabled: [0x%x, 0x%x] focus=[0x%x, 0x%x] size=0x%x%n",
                    begin, end,
                    LADON_ARG4_TRACE_ADDRESS,
                    end,
                    LADON_ARG4_TRACE_SIZE);
            ladonArg4WriteTrace = emulator.traceWrite(begin, end);
        }
        if (ENABLE_LADON_STAGE0_TRACE) {
            long begin = LADON_STAGE0_TRACE_ADDRESS - LADON_STAGE0_TRACE_PAD;
            long end = LADON_STAGE0_TRACE_ADDRESS + LADON_STAGE0_TRACE_SIZE + LADON_STAGE0_TRACE_PAD - 1L;
            System.out.printf("ladon stage0 trace enabled: [0x%x, 0x%x] focus=[0x%x, 0x%x] size=0x%x%n",
                    begin, end,
                    LADON_STAGE0_TRACE_ADDRESS,
                    LADON_STAGE0_TRACE_ADDRESS + LADON_STAGE0_TRACE_SIZE - 1L,
                    LADON_STAGE0_TRACE_SIZE);
            ladonStage0WriteTrace = emulator.traceWrite(begin, end);
        }
        if (ENABLE_LADON_STAGE0_SYSTEM_WRITE_TRACE) {
            long begin = LADON_STAGE0_TRACE_ADDRESS - LADON_STAGE0_TRACE_PAD;
            long end = LADON_STAGE0_TRACE_ADDRESS + LADON_STAGE0_TRACE_SIZE + LADON_STAGE0_TRACE_PAD;
            System.out.printf("ladon stage0 system write trace enabled: [0x%x, 0x%x) focus=[0x%x, 0x%x] size=0x%x%n",
                    begin,
                    end,
                    LADON_STAGE0_TRACE_ADDRESS,
                    LADON_STAGE0_TRACE_ADDRESS + LADON_STAGE0_TRACE_SIZE - 1L,
                    LADON_STAGE0_TRACE_SIZE);
            emulator.setTraceSystemMemoryWrite(begin, end, (emu, address, buf) -> {
                UnidbgPointer pc = emu.getContext().getPCPointer();
                UnidbgPointer lr = emu.getContext().getLRPointer();
                String hex = Hex.encodeHexString(buf);
                String text = new String(buf, StandardCharsets.UTF_8)
                        .replace("\r", "\\r")
                        .replace("\n", "\\n");
                System.out.printf("[ladon stage0 system write] addr=0x%x size=%d pc=%s lr=%s hex=%s text=%s%n",
                        address, buf.length, pc, lr, hex, text);
            });
        }
        if (ENABLE_LADON_SRC_TRACE) {
            long begin = LADON_SRC_TRACE_ADDRESS;
            long end = LADON_SRC_TRACE_ADDRESS + LADON_SRC_TRACE_SIZE - 1L;
            System.out.printf("ladon src trace enabled: [0x%x, 0x%x] focus=[0x%x, 0x%x] size=0x%x%n",
                    begin, end,
                    LADON_SRC_TRACE_ADDRESS,
                    end,
                    LADON_SRC_TRACE_SIZE);
            ladonSrcWriteTrace = emulator.traceWrite(begin, end);
        }
        if (ENABLE_LADON_SRC_SYSTEM_WRITE_TRACE) {
            long begin = LADON_SRC_TRACE_ADDRESS;
            long end = LADON_SRC_TRACE_ADDRESS + LADON_SRC_TRACE_SIZE;
            System.out.printf("ladon src system write trace enabled: [0x%x, 0x%x) focus=[0x%x, 0x%x] size=0x%x%n",
                    begin,
                    end,
                    LADON_SRC_TRACE_ADDRESS,
                    LADON_SRC_TRACE_ADDRESS + LADON_SRC_TRACE_SIZE - 1L,
                    LADON_SRC_TRACE_SIZE);
            emulator.setTraceSystemMemoryWrite(begin, end, (emu, address, buf) -> {
                UnidbgPointer pc = emu.getContext().getPCPointer();
                UnidbgPointer lr = emu.getContext().getLRPointer();
                String hex = Hex.encodeHexString(buf);
                String text = new String(buf, StandardCharsets.UTF_8)
                        .replace("\r", "\\r")
                        .replace("\n", "\\n");
                System.out.printf("[ladon src system write] addr=0x%x size=%d pc=%s lr=%s hex=%s text=%s%n",
                        address, buf.length, pc, lr, hex, text);
            });
        }
        if (ENABLE_LADON_SRC_SOURCE_TRACE) {
            long begin = LADON_SRC_SOURCE_TRACE_ADDRESS;
            long end = LADON_SRC_SOURCE_TRACE_ADDRESS + LADON_SRC_SOURCE_TRACE_SIZE - 1L;
            System.out.printf("ladon src-source trace enabled: [0x%x, 0x%x] focus=[0x%x, 0x%x] size=0x%x%n",
                    begin, end,
                    LADON_SRC_SOURCE_TRACE_ADDRESS,
                    end,
                    LADON_SRC_SOURCE_TRACE_SIZE);
            ladonSrcSourceWriteTrace = emulator.traceWrite(begin, end);
        }
        if (ENABLE_LADON_SRC_SOURCE_SYSTEM_WRITE_TRACE) {
            long begin = LADON_SRC_SOURCE_TRACE_ADDRESS;
            long end = LADON_SRC_SOURCE_TRACE_ADDRESS + LADON_SRC_SOURCE_TRACE_SIZE;
            System.out.printf("ladon src-source system write trace enabled: [0x%x, 0x%x) focus=[0x%x, 0x%x] size=0x%x%n",
                    begin,
                    end,
                    LADON_SRC_SOURCE_TRACE_ADDRESS,
                    LADON_SRC_SOURCE_TRACE_ADDRESS + LADON_SRC_SOURCE_TRACE_SIZE - 1L,
                    LADON_SRC_SOURCE_TRACE_SIZE);
            emulator.setTraceSystemMemoryWrite(begin, end, (emu, address, buf) -> {
                UnidbgPointer pc = emu.getContext().getPCPointer();
                UnidbgPointer lr = emu.getContext().getLRPointer();
                String hex = Hex.encodeHexString(buf);
                String text = new String(buf, StandardCharsets.UTF_8)
                        .replace("\r", "\\r")
                        .replace("\n", "\\n");
                System.out.printf("[ladon src-source system write] addr=0x%x size=%d pc=%s lr=%s hex=%s text=%s%n",
                        address, buf.length, pc, lr, hex, text);
            });
        }
        if (ENABLE_LADON_SLOT9_TRACE) {
            long begin = LADON_SLOT9_TRACE_ADDRESS;
            long end = LADON_SLOT9_TRACE_ADDRESS + LADON_SLOT9_TRACE_SIZE - 1L;
            System.out.printf("ladon slot9 trace enabled: [0x%x, 0x%x] focus=[0x%x, 0x%x] size=0x%x%n",
                    begin, end,
                    LADON_SLOT9_TRACE_ADDRESS,
                    end,
                    LADON_SLOT9_TRACE_SIZE);
            ladonSlot9WriteTrace = emulator.traceWrite(begin, end);
        }
        if (ENABLE_LADON_SLOT9_SYSTEM_WRITE_TRACE) {
            long begin = LADON_SLOT9_TRACE_ADDRESS;
            long end = LADON_SLOT9_TRACE_ADDRESS + LADON_SLOT9_TRACE_SIZE;
            System.out.printf("ladon slot9 system write trace enabled: [0x%x, 0x%x) focus=[0x%x, 0x%x] size=0x%x%n",
                    begin,
                    end,
                    LADON_SLOT9_TRACE_ADDRESS,
                    LADON_SLOT9_TRACE_ADDRESS + LADON_SLOT9_TRACE_SIZE - 1L,
                    LADON_SLOT9_TRACE_SIZE);
            emulator.setTraceSystemMemoryWrite(begin, end, (emu, address, buf) -> {
                UnidbgPointer pc = emu.getContext().getPCPointer();
                UnidbgPointer lr = emu.getContext().getLRPointer();
                String hex = Hex.encodeHexString(buf);
                String text = new String(buf, StandardCharsets.UTF_8)
                        .replace("\r", "\\r")
                        .replace("\n", "\\n");
                System.out.printf("[ladon slot9 system write] addr=0x%x size=%d pc=%s lr=%s hex=%s text=%s%n",
                        address, buf.length, pc, lr, hex, text);
            });
        }
        if (ENABLE_LADON_SYSTEM_WRITE_TRACE) {
            long begin = LADON_VALUE_TRACE_ADDRESS - LADON_VALUE_TRACE_PAD;
            long end = LADON_VALUE_TRACE_ADDRESS + LADON_VALUE_TRACE_SIZE + LADON_VALUE_TRACE_PAD;
            System.out.printf("ladon system write trace enabled: [0x%x, 0x%x) focus=[0x%x, 0x%x] size=0x%x%n",
                    begin,
                    end,
                    LADON_VALUE_TRACE_ADDRESS,
                    LADON_VALUE_TRACE_ADDRESS + LADON_VALUE_TRACE_SIZE - 1L,
                    LADON_VALUE_TRACE_SIZE);
            emulator.setTraceSystemMemoryWrite(begin, end, (emu, address, buf) -> {
                UnidbgPointer pc = emu.getContext().getPCPointer();
                UnidbgPointer lr = emu.getContext().getLRPointer();
                String hex = Hex.encodeHexString(buf);
                String text = new String(buf, StandardCharsets.UTF_8)
                        .replace("\r", "\\r")
                        .replace("\n", "\\n");
                System.out.printf("[ladon system write] addr=0x%x size=%d pc=%s lr=%s hex=%s text=%s%n",
                        address, buf.length, pc, lr, hex, text);
            });
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
            if (ladonStage0WriteTrace != null) {
                ladonStage0WriteTrace.stopTrace();
                ladonStage0WriteTrace = null;
            }
            if (ladonSrcWriteTrace != null) {
                ladonSrcWriteTrace.stopTrace();
                ladonSrcWriteTrace = null;
            }
            if (ladonSrcSourceWriteTrace != null) {
                ladonSrcSourceWriteTrace.stopTrace();
                ladonSrcSourceWriteTrace = null;
            }
            if (ladonSlot9WriteTrace != null) {
                ladonSlot9WriteTrace.stopTrace();
                ladonSlot9WriteTrace = null;
            }
            if (ladonGlobalWordWriteTrace != null) {
                ladonGlobalWordWriteTrace.stopTrace();
                ladonGlobalWordWriteTrace = null;
                ladonGlobalWordTraceBase = 0;
            }
            if (ladonArg4WriteTrace != null) {
                ladonArg4WriteTrace.stopTrace();
                ladonArg4WriteTrace = null;
            }
            if (ladonValueWriteTrace != null) {
                ladonValueWriteTrace.stopTrace();
                ladonValueWriteTrace = null;
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

    // 按运行时解析出的全局字地址开启 4 字节写监控，用来追 slot[6] 的真正来源。
    private void ensureLadonGlobalWordWriteTrace(UnidbgPointer globalWordPtr) {
        if (!ENABLE_LADON_GLOBAL_WORD_TRACE || globalWordPtr == null) {
            return;
        }
        long base = globalWordPtr.peer;
        if (ladonGlobalWordWriteTrace != null && ladonGlobalWordTraceBase == base) {
            return;
        }
        if (ladonGlobalWordWriteTrace != null) {
            ladonGlobalWordWriteTrace.stopTrace();
            ladonGlobalWordWriteTrace = null;
        }
        long end = base + LADON_GLOBAL_WORD_TRACE_SIZE - 1L;
        System.out.printf("ladon global-word trace enabled: [0x%x, 0x%x] size=0x%x%n",
                base, end, LADON_GLOBAL_WORD_TRACE_SIZE);
        ladonGlobalWordWriteTrace = emulator.traceWrite(base, end);
        ladonGlobalWordTraceBase = base;
    }

    // 只记录真正命中 slot[122] 地址范围的 VM 写回，避开普通内存写的栈噪音。
    private void maybeLogStage0VmSlotWrite(Emulator<?> emulator, long offset, Instruction insn) {
        if (!ENABLE_LADON_STAGE0_VM_SLOT_LOG) {
            return;
        }
        if (offset < METASEC_VM_SLOT_WRITE_SCAN_BEGIN || offset > METASEC_VM_SLOT_WRITE_SCAN_END) {
            return;
        }
        int insnId = insn.getId();
        if (insnId != Arm64_const.ARM64_INS_STR &&
                insnId != Arm64_const.ARM64_INS_STUR &&
                insnId != Arm64_const.ARM64_INS_STP &&
                insnId != Arm64_const.ARM64_INS_STNP &&
                insnId != Arm64_const.ARM64_INS_STRB &&
                insnId != Arm64_const.ARM64_INS_STURB &&
                insnId != Arm64_const.ARM64_INS_STRH &&
                insnId != Arm64_const.ARM64_INS_STURH) {
            return;
        }
        Object rawOpInfo = insn.getOperands();
        if (!(rawOpInfo instanceof OpInfo)) {
            return;
        }
        Operand[] operands = ((OpInfo) rawOpInfo).getOperands();
        if (operands == null || operands.length < 2) {
            return;
        }
        Operand memOp = operands[operands.length - 1];
        if (memOp.getType() != Arm64_const.ARM64_OP_MEM) {
            return;
        }
        List<Integer> srcRegs = new ArrayList<>();
        for (int i = 0; i < operands.length - 1; i++) {
            Operand srcOp = operands[i];
            if (srcOp.getType() != Arm64_const.ARM64_OP_REG) {
                return;
            }
            srcRegs.add(srcOp.getValue().getReg());
        }
        if (srcRegs.isEmpty()) {
            return;
        }
        MemType mem = memOp.getValue().getMem();
        if (mem == null || mem.getBase() == Arm64_const.ARM64_REG_INVALID) {
            return;
        }
        String baseRegName = insn.regName(mem.getBase());
        if (!"x24".equals(baseRegName)) {
            return;
        }
        long slotBaseValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X24).longValue();
        int indexReg = mem.getIndex();
        long indexContribution = 0;
        String indexDesc = "none";
        if (indexReg != Arm64_const.ARM64_REG_INVALID) {
            int unicornIndexReg = insn.mapToUnicornReg(indexReg);
            long rawIndex = emulator.getBackend().reg_read(unicornIndexReg).longValue();
            indexContribution = computeArm64MemIndex(insn, memOp, indexReg, rawIndex);
            indexDesc = describeArm64MemIndex(insn, memOp, indexReg, rawIndex, indexContribution);
        }
        long dstAddress = slotBaseValue + mem.getDisp() + indexContribution;
        int storeWidth = guessArm64StoreWidthBytes(insn, srcRegs);
        long slotDelta = dstAddress - slotBaseValue;
        long stage0SlotOffset = (long) LADON_STAGE0_SLOT_INDEX * METASEC_VM_SLOT_STRIDE;
        if (!rangesOverlap(slotDelta, storeWidth, stage0SlotOffset, METASEC_VM_SLOT_STRIDE)) {
            return;
        }
        String slotText = slotDelta >= 0 && slotDelta % 8L == 0
                ? Long.toString(slotDelta / 8L)
                : "unaligned";
        StringBuilder srcDesc = new StringBuilder();
        for (int i = 0; i < srcRegs.size(); i++) {
            int srcReg = srcRegs.get(i);
            int unicornSrcReg = insn.mapToUnicornReg(srcReg);
            long srcRaw = emulator.getBackend().reg_read(unicornSrcReg).longValue();
            if (i != 0) {
                srcDesc.append(", ");
            }
            srcDesc.append(insn.regName(srcReg)).append("=0x").append(Long.toHexString(srcRaw));
        }
        System.out.printf("[metasec+0x%x] vm-slot-write-stage0 insn=%s %s slotBase=0x%x dst=0x%x width=%d slot=%s targetSlot=%d src={%s} disp=%d index={%s}%n",
                offset,
                insn.getMnemonic(),
                insn.getOpStr(),
                slotBaseValue,
                dstAddress,
                storeWidth,
                slotText,
                LADON_STAGE0_SLOT_INDEX,
                srcDesc,
                mem.getDisp(),
                indexDesc);
    }

    // 只记录真正命中 slot[9] 地址范围的 VM 写回，帮助追 X-Ladon 上游值的来源。
    private void maybeLogLadonSlot9VmWrite(Emulator<?> emulator, long offset, Instruction insn) {
        if (!ENABLE_LOG_COPY_SOURCES) {
            return;
        }
        if (offset < METASEC_VM_SLOT_WRITE_SCAN_BEGIN || offset > METASEC_VM_SLOT_WRITE_SCAN_END) {
            return;
        }
        int insnId = insn.getId();
        if (insnId != Arm64_const.ARM64_INS_STR &&
                insnId != Arm64_const.ARM64_INS_STUR &&
                insnId != Arm64_const.ARM64_INS_STP &&
                insnId != Arm64_const.ARM64_INS_STNP &&
                insnId != Arm64_const.ARM64_INS_STRB &&
                insnId != Arm64_const.ARM64_INS_STURB &&
                insnId != Arm64_const.ARM64_INS_STRH &&
                insnId != Arm64_const.ARM64_INS_STURH) {
            return;
        }
        Object rawOpInfo = insn.getOperands();
        if (!(rawOpInfo instanceof OpInfo)) {
            return;
        }
        Operand[] operands = ((OpInfo) rawOpInfo).getOperands();
        if (operands == null || operands.length < 2) {
            return;
        }
        Operand memOp = operands[operands.length - 1];
        if (memOp.getType() != Arm64_const.ARM64_OP_MEM) {
            return;
        }
        List<Integer> srcRegs = new ArrayList<>();
        for (int i = 0; i < operands.length - 1; i++) {
            Operand srcOp = operands[i];
            if (srcOp.getType() != Arm64_const.ARM64_OP_REG) {
                return;
            }
            srcRegs.add(srcOp.getValue().getReg());
        }
        if (srcRegs.isEmpty()) {
            return;
        }
        MemType mem = memOp.getValue().getMem();
        if (mem == null || mem.getBase() == Arm64_const.ARM64_REG_INVALID) {
            return;
        }
        String baseRegName = insn.regName(mem.getBase());
        if (!"x24".equals(baseRegName)) {
            return;
        }
        long slotBaseValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X24).longValue();
        int indexReg = mem.getIndex();
        long indexContribution = 0;
        String indexDesc = "none";
        if (indexReg != Arm64_const.ARM64_REG_INVALID) {
            int unicornIndexReg = insn.mapToUnicornReg(indexReg);
            long rawIndex = emulator.getBackend().reg_read(unicornIndexReg).longValue();
            indexContribution = computeArm64MemIndex(insn, memOp, indexReg, rawIndex);
            indexDesc = describeArm64MemIndex(insn, memOp, indexReg, rawIndex, indexContribution);
        }
        long dstAddress = slotBaseValue + mem.getDisp() + indexContribution;
        int storeWidth = guessArm64StoreWidthBytes(insn, srcRegs);
        long slotDelta = dstAddress - slotBaseValue;
        long slot9Offset = (long) LADON_VM_GLOBAL_SOURCE_SLOT * METASEC_VM_SLOT_STRIDE;
        if (!rangesOverlap(slotDelta, storeWidth, slot9Offset, METASEC_VM_SLOT_STRIDE)) {
            return;
        }
        String slotText = slotDelta >= 0 && slotDelta % 8L == 0
                ? Long.toString(slotDelta / 8L)
                : "unaligned";
        StringBuilder srcDesc = new StringBuilder();
        for (int i = 0; i < srcRegs.size(); i++) {
            int srcReg = srcRegs.get(i);
            int unicornSrcReg = insn.mapToUnicornReg(srcReg);
            long srcRaw = emulator.getBackend().reg_read(unicornSrcReg).longValue();
            if (i != 0) {
                srcDesc.append(", ");
            }
            srcDesc.append(insn.regName(srcReg)).append("=0x").append(Long.toHexString(srcRaw));
        }
        System.out.printf("[metasec+0x%x] vm-slot-write-ladon9 insn=%s %s slotBase=0x%x dst=0x%x width=%d slot=%s targetSlot=%d src={%s} disp=%d index={%s}%n",
                offset,
                insn.getMnemonic(),
                insn.getOpStr(),
                slotBaseValue,
                dstAddress,
                storeWidth,
                slotText,
                LADON_VM_GLOBAL_SOURCE_SLOT,
                srcDesc,
                mem.getDisp(),
                indexDesc);
    }

    // 对 copy 型 slot 写回补充 src/dst slot 号和值，只在目标是 slot[9] 时打印。
    private void logLadonSlotCopyPreload(Emulator<?> emulator, long offset, String tag, int srcSlot, int dstSlot) {
        if (dstSlot != LADON_VM_GLOBAL_SOURCE_SLOT) {
            return;
        }
        long slotBaseValue = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X24).longValue();
        UnidbgPointer slotBase = UnidbgPointer.pointer(emulator, slotBaseValue);
        long srcCell = slotBaseValue + (long) srcSlot * METASEC_VM_SLOT_STRIDE;
        long dstCell = slotBaseValue + (long) dstSlot * METASEC_VM_SLOT_STRIDE;
        long srcValue = slotBase == null ? 0L : slotBase.getLong((long) srcSlot * METASEC_VM_SLOT_STRIDE);
        long dstBefore = slotBase == null ? 0L : slotBase.getLong((long) dstSlot * METASEC_VM_SLOT_STRIDE);
        System.out.printf("[metasec+0x%x] %s slotBase=%s srcSlot=%d srcCell=0x%x srcValue=0x%x dstSlot=%d dstCell=0x%x dstBefore=0x%x%n",
                offset,
                tag,
                slotBase,
                srcSlot,
                srcCell,
                srcValue,
                dstSlot,
                dstCell,
                dstBefore);
    }

    // 计算 ARM64 内存寻址里的 index 部分，供 slot 写回定位使用。
    private long computeArm64MemIndex(Instruction insn, Operand memOp, int indexReg, long rawIndex) {
        String regName = insn.regName(indexReg);
        long value = rawIndex;
        if (regName != null && regName.startsWith("w")) {
            value &= 0xffffffffL;
        }
        switch (memOp.getExt()) {
            case Arm64_const.ARM64_EXT_UXTW:
                value &= 0xffffffffL;
                break;
            case Arm64_const.ARM64_EXT_SXTW:
                value = (long) (int) value;
                break;
            case Arm64_const.ARM64_EXT_UXTX:
            case Arm64_const.ARM64_EXT_SXTX:
            case Arm64_const.ARM64_EXT_INVALID:
            default:
                break;
        }
        OpShift shift = memOp.getShift();
        if (shift != null && shift.getValue() != 0) {
            value <<= shift.getValue();
        }
        return value;
    }

    // 输出 index 寄存器、扩展方式和缩放信息，方便确认 slot 号是怎么来的。
    private String describeArm64MemIndex(Instruction insn, Operand memOp, int indexReg, long rawIndex, long indexContribution) {
        OpShift shift = memOp.getShift();
        int shiftValue = shift == null ? 0 : shift.getValue();
        int shiftType = shift == null ? Arm64_const.ARM64_SFT_INVALID : shift.getType();
        return String.format("reg=%s raw=0x%x ext=%s shift=%s:%d scaled=0x%x",
                insn.regName(indexReg),
                rawIndex,
                describeArm64Ext(memOp.getExt()),
                describeArm64Shift(shiftType),
                shiftValue,
                indexContribution);
    }

    // 估算 store 指令写入的字节数，用来判断是否和 slot[122] 地址范围重叠。
    private int guessArm64StoreWidthBytes(Instruction insn, List<Integer> srcRegs) {
        switch (insn.getId()) {
            case Arm64_const.ARM64_INS_STRB:
            case Arm64_const.ARM64_INS_STURB:
                return 1;
            case Arm64_const.ARM64_INS_STRH:
            case Arm64_const.ARM64_INS_STURH:
                return 2;
            default:
                int width = 0;
                for (int srcReg : srcRegs) {
                    width += guessArm64RegisterWidthBytes(insn.regName(srcReg));
                }
                return width > 0 ? width : 8;
        }
    }

    // 按寄存器名估算存储宽度，兼容 q/d/s/w/x 以及 stp 这类双寄存器写。
    private int guessArm64RegisterWidthBytes(String regName) {
        if (regName == null || regName.isEmpty()) {
            return 8;
        }
        char prefix = regName.charAt(0);
        switch (prefix) {
            case 'b':
                return 1;
            case 'h':
                return 2;
            case 's':
            case 'w':
                return 4;
            case 'd':
            case 'x':
                return 8;
            case 'q':
                return 16;
            default:
                return 8;
        }
    }

    // 判断两段地址范围是否相交。
    private boolean rangesOverlap(long beginA, int sizeA, long beginB, int sizeB) {
        if (sizeA <= 0 || sizeB <= 0) {
            return false;
        }
        long endA = beginA + sizeA - 1L;
        long endB = beginB + sizeB - 1L;
        return beginA <= endB && beginB <= endA;
    }

    // 将 ARM64 extend 类型格式化为短文本。
    private String describeArm64Ext(int ext) {
        switch (ext) {
            case Arm64_const.ARM64_EXT_UXTW:
                return "uxtw";
            case Arm64_const.ARM64_EXT_SXTW:
                return "sxtw";
            case Arm64_const.ARM64_EXT_UXTX:
                return "uxtx";
            case Arm64_const.ARM64_EXT_SXTX:
                return "sxtx";
            case Arm64_const.ARM64_EXT_INVALID:
                return "none";
            default:
                return "ext#" + ext;
        }
    }

    // 将 ARM64 shift 类型格式化为短文本。
    private String describeArm64Shift(int shiftType) {
        switch (shiftType) {
            case Arm64_const.ARM64_SFT_LSL:
                return "lsl";
            case Arm64_const.ARM64_SFT_LSR:
                return "lsr";
            case Arm64_const.ARM64_SFT_ASR:
                return "asr";
            case Arm64_const.ARM64_SFT_ROR:
                return "ror";
            case Arm64_const.ARM64_SFT_MSL:
                return "msl";
            case Arm64_const.ARM64_SFT_INVALID:
                return "none";
            default:
                return "shift#" + shiftType;
        }
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

    // 将可能读取失败的 64 位值格式化为文本。
    private String formatMaybeHex(long value) {
        return value == Long.MIN_VALUE ? "<read-failed>" : String.format("0x%x", value);
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
