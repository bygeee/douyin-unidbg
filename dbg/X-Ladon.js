/*
 * Frida 17.9.1
 *
 * Usage:
 *   frida -U -f com.ss.android.ugc.aweme -q -l dbg/X-Ladon.js
 *   frida -U -n com.ss.android.ugc.aweme -q -l dbg/X-Ladon.js
 *
 * Purpose:
 *   Trace the native X-Ladon generation chain inside libmetasec_ml.so.
 */

"use strict";

const TARGET_MODULE = "libmetasec_ml.so";
const MASK64 = (1n << 64n) - 1n;
const ACTIVE_THREAD_TTL_MS = 5000;

const OFF = {
    componentInsert: 0x2b7724,
    ladonSlot6HashPrecall: 0x2be3ec,
    ladonGlobalSetPrecall: 0x2be434,
    ladonSlot6SourcePrecall: 0x2be454,
    ladonSlot6SourcePostcall: 0x2be458,
    ladonGlobalWordLoad: 0x29fbac,

    vmXor64ToSlot: 0x2d15e8,
    vmDerefToSlot: 0x2def2c,
    vmDerefToSlot2: 0x2e4248,
    vmXor64CompositeToSlot: 0x304ae0,
    vmRor64ToSlot: 0x2d2094,

    vmLsl32Load: 0x2cf174,
    vmLsl32Shift: 0x2cf178,
    vmRev16ToSlot: 0x2d0f58,
    vmRor32ToSlot: 0x2cea04,
    vmStore32: 0x2cead4,
    ladonBase64Call: 0x269dd8,
};

const SLOT = {
    result32: 5,
    hash64: 6,
    globalLow32: 9,
    ror64Source: 20,
};

const STATE = {
    installed: false,
    module: null,
    base: null,
    activeThreads: new Map(),
};

function log(message) {
    console.log(message);
}

function markThreadActive() {
    STATE.activeThreads.set(Process.getCurrentThreadId(), Date.now());
}

function isThreadActive() {
    const threadId = Process.getCurrentThreadId();
    const seenAt = STATE.activeThreads.get(threadId);
    if (seenAt === undefined) {
        return false;
    }
    if ((Date.now() - seenAt) > ACTIVE_THREAD_TTL_MS) {
        STATE.activeThreads.delete(threadId);
        return false;
    }
    return true;
}

function ptrHex(p) {
    if (p === null || p === undefined) {
        return "0x0";
    }
    try {
        return ptr(p).toString();
    } catch (e) {
        return String(p);
    }
}

function npToBigInt(value) {
    return BigInt(ptr(value).toString());
}

function hex32(value) {
    return `0x${(value >>> 0).toString(16)}`;
}

function hex64(value) {
    return `0x${(value & MASK64).toString(16)}`;
}

function addU64(a, b) {
    return (a + b) & MASK64;
}

function xorU64(a, b) {
    return (a ^ b) & MASK64;
}

function ror64(value, bits) {
    const shift = BigInt(bits & 63);
    if (shift === 0n) {
        return value & MASK64;
    }
    return ((value >> shift) | (value << (64n - shift))) & MASK64;
}

function rev16_32(value) {
    const v = value >>> 0;
    return ((((v & 0x00ff00ff) << 8) | ((v & 0xff00ff00) >>> 8)) >>> 0);
}

function ror32(value, bits) {
    const rot = bits & 31;
    const v = value >>> 0;
    return (((v >>> rot) | (v << (32 - rot))) >>> 0);
}

function safeReadByteArray(address, size) {
    try {
        return Memory.readByteArray(ptr(address), size);
    } catch (e) {
        return null;
    }
}

function byteArrayToU8(bytes) {
    if (bytes === null) {
        return null;
    }
    return new Uint8Array(bytes);
}

function bytesToHex(bytes) {
    if (bytes === null) {
        return "<read-failed>";
    }
    const view = byteArrayToU8(bytes);
    let out = "";
    for (let i = 0; i < view.length; i += 1) {
        out += view[i].toString(16).padStart(2, "0");
    }
    return out;
}

function bytesToAscii(bytes) {
    if (bytes === null) {
        return "<read-failed>";
    }
    const view = byteArrayToU8(bytes);
    let out = "";
    for (let i = 0; i < view.length; i += 1) {
        const ch = view[i];
        if (ch >= 0x20 && ch <= 0x7e) {
            out += String.fromCharCode(ch);
        } else if (ch === 0x0a) {
            out += "\\n";
        } else if (ch === 0x0d) {
            out += "\\r";
        } else if (ch === 0x00) {
            out += "\\0";
        } else {
            out += ".";
        }
    }
    return out;
}

function describeBuffer(address, size) {
    if (address === null || ptr(address).isNull()) {
        return "hex=<null> text=<null>";
    }
    if (size <= 0) {
        return "hex= text=";
    }
    const data = safeReadByteArray(address, size);
    return `hex=${bytesToHex(data)} text=${bytesToAscii(data)}`;
}

function safeReadU32(address) {
    try {
        return Memory.readU32(ptr(address)) >>> 0;
    } catch (e) {
        return null;
    }
}

function safeReadPointer(address) {
    try {
        return Memory.readPointer(ptr(address));
    } catch (e) {
        return null;
    }
}

function safeReadU64BigInt(address) {
    const data = safeReadByteArray(address, 8);
    if (data === null) {
        return null;
    }
    const view = byteArrayToU8(data);
    let value = 0n;
    for (let i = 7; i >= 0; i -= 1) {
        value = (value << 8n) | BigInt(view[i]);
    }
    return value;
}

function readSlotU64(slotBase, slotIndex) {
    if (slotBase === null || ptr(slotBase).isNull()) {
        return null;
    }
    return safeReadU64BigInt(ptr(slotBase).add(slotIndex * 8));
}

function readLenDataObject(address) {
    if (address === null || ptr(address).isNull()) {
        return "null";
    }
    try {
        const obj = ptr(address);
        const len = obj.add(0xc).readU32() >>> 0;
        const data = obj.add(0x10).readPointer();
        return `obj=${obj} len=${len} data=${data} ${describeBuffer(data, Math.min(len, 0x80))}`;
    } catch (e) {
        return `obj=${ptrHex(address)} <decode failed: ${e.message}>`;
    }
}

function readMssdkStringRef(address) {
    if (address === null || ptr(address).isNull()) {
        return null;
    }
    try {
        const ref = ptr(address);
        const alloc = ref.add(8).readU32() >>> 0;
        const len = ref.add(12).readU32() >>> 0;
        const data = ref.add(16).readPointer();
        const text = bytesToAscii(safeReadByteArray(data, Math.min(len, 0x100)));
        return {
            ref,
            alloc,
            len,
            data,
            text,
            desc: `ref=${ref} alloc=${alloc} len=${len} data=${data} ${describeBuffer(data, Math.min(len, 0x100))}`,
        };
    } catch (e) {
        return {
            ref: ptr(address),
            desc: `ref=${ptrHex(address)} <decode failed: ${e.message}>`,
            text: null,
        };
    }
}

function contextU32(ctx, regName) {
    return Number(npToBigInt(ctx[regName]) & 0xffffffffn) >>> 0;
}

function contextU64(ctx, regName) {
    return npToBigInt(ctx[regName]) & MASK64;
}

function contextPtr(ctx, regName) {
    return ptr(ctx[regName]);
}

function logVmXor64ToSlot(ctx, offset) {
    const srcSlotA = contextU32(ctx, "x9");
    const srcSlotB = contextU32(ctx, "x10");
    const dstSlot = contextU32(ctx, "x12");
    if (dstSlot !== SLOT.hash64 && dstSlot !== SLOT.globalLow32 && dstSlot !== SLOT.ror64Source) {
        return;
    }

    const slotBase = contextPtr(ctx, "x24");
    const srcValueA = readSlotU64(slotBase, srcSlotA);
    const srcValueB = readSlotU64(slotBase, srcSlotB);
    if (srcValueA === null || srcValueB === null) {
        return;
    }

    const result = xorU64(srcValueB, srcValueA);
    const dstCell = slotBase.add(dstSlot * 8);
    log(`[metasec+0x${offset.toString(16)}] vm-xor64-to-slot slotBase=${slotBase} srcSlotA=${srcSlotA} srcValueA=${hex64(srcValueA)} srcSlotB=${srcSlotB} srcValueB=${hex64(srcValueB)} dstSlot=${dstSlot} result=${hex64(result)} dstCell=${dstCell}`);
}

function logVmDerefToSlot(ctx, offset, tag) {
    const dstSlot = contextU32(ctx, "x8") & 0xff;
    if (dstSlot !== SLOT.result32 && dstSlot !== SLOT.globalLow32 && dstSlot !== SLOT.ror64Source) {
        return;
    }

    const srcBaseSlot = contextU32(ctx, "x11") & 0xff;
    const off = contextU64(ctx, "x14");
    const slotBase = contextPtr(ctx, "x24");
    const srcBaseValue = readSlotU64(slotBase, srcBaseSlot);
    if (srcBaseValue === null) {
        return;
    }

    const srcBasePtr = ptr(srcBaseValue.toString());
    const loaded = safeReadU64BigInt(srcBasePtr.add(Number(off & 0xffffffffn)));
    const dstCell = slotBase.add(dstSlot * 8);
    log(`[metasec+0x${offset.toString(16)}] ${tag} slotBase=${slotBase} srcBaseSlot=${srcBaseSlot} srcBaseValue=${hex64(srcBaseValue)} off=${hex64(off)} dstSlot=${dstSlot} loaded=${loaded === null ? "<read-failed>" : hex64(loaded)} dstCell=${dstCell}`);
}

function logVmXor64CompositeToSlot(ctx, offset) {
    const srcSlotA = contextU32(ctx, "x10") & 0xff;
    const srcSlotB = contextU32(ctx, "x13") & 0xff;
    const dstSlot = contextU32(ctx, "x11") & 0xff;
    if (dstSlot !== SLOT.result32 && dstSlot !== SLOT.globalLow32 && dstSlot !== SLOT.ror64Source) {
        return;
    }

    const srcValueA = contextU64(ctx, "x10");
    const srcValueB = contextU64(ctx, "x13");
    const slotBase = contextPtr(ctx, "x12");
    const result = xorU64(srcValueB, srcValueA);
    const dstCell = slotBase.add(dstSlot * 8);
    log(`[metasec+0x${offset.toString(16)}] vm-xor64-composite-to-slot slotBase=${slotBase} srcSlotA=${srcSlotA} srcValueA=${hex64(srcValueA)} srcSlotB=${srcSlotB} srcValueB=${hex64(srcValueB)} dstSlot=${dstSlot} result=${hex64(result)} dstCell=${dstCell}`);
}

function logVmRor64ToSlot(ctx, offset) {
    const srcSlot = contextU32(ctx, "x9") & 0xff;
    const rot = contextU32(ctx, "x11") & 63;
    const dstSlot = contextU32(ctx, "x12") & 0xff;
    if (dstSlot !== SLOT.ror64Source && dstSlot !== SLOT.result32) {
        return;
    }

    const slotBase = contextPtr(ctx, "x24");
    const srcValue = readSlotU64(slotBase, srcSlot);
    if (srcValue === null) {
        return;
    }

    const result = ror64(srcValue, rot);
    const dstCell = slotBase.add(dstSlot * 8);
    log(`[metasec+0x${offset.toString(16)}] vm-ror64-to-slot slotBase=${slotBase} srcSlot=${srcSlot} srcValue=${hex64(srcValue)} dstSlot=${dstSlot} rot=${rot} result=${hex64(result)} dstCell=${dstCell}`);
}

function logVmLsl32Load(ctx, offset) {
    const srcSlot = contextU32(ctx, "x9");
    const dstSlot = contextU32(ctx, "x8");
    const shift = contextU32(ctx, "x11") & 31;
    if (dstSlot !== SLOT.result32) {
        return;
    }

    const slotBase = contextPtr(ctx, "x24");
    const srcRaw = contextU32(ctx, "x10");
    const slotMemRawBig = readSlotU64(slotBase, srcSlot);
    const result32 = (srcRaw << shift) >>> 0;
    const srcCell = slotBase.add(srcSlot * 8);
    const dstCell = slotBase.add(dstSlot * 8);
    log(`[metasec+0x${offset.toString(16)}] vm-lsl32-load slotBase=${slotBase} srcSlot=${srcSlot} srcCell=${srcCell} slotMemRaw=${slotMemRawBig === null ? "<read-failed>" : hex64(slotMemRawBig)} x10Loaded=${hex32(srcRaw)} dstSlot=${dstSlot} shift=${shift} src32=${hex32(srcRaw)} result32=${hex32(result32)} dstCell=${dstCell}`);
}

function logVmLsl32Shift(ctx, offset) {
    const dstSlot = contextU32(ctx, "x9");
    const shift = contextU32(ctx, "x11") & 31;
    if (dstSlot !== SLOT.result32) {
        return;
    }

    const slotBase = contextPtr(ctx, "x24");
    const opcodeSel = contextU64(ctx, "x12");
    const srcRaw = contextU32(ctx, "x10");
    const result32 = (srcRaw << shift) >>> 0;
    const dstCell = slotBase.add(dstSlot * 8);
    log(`[metasec+0x${offset.toString(16)}] vm-lsl32-shift opcodeSel=${hex64(opcodeSel)} dstSlot=${dstSlot} shift=${shift} srcRaw=${hex32(srcRaw)} src32=${hex32(srcRaw)} result32=${hex32(result32)} dstCell=${dstCell}`);
}

function logVmRev16ToSlot(ctx, offset) {
    const srcSlot = contextU32(ctx, "x9");
    const dstSlot = contextU32(ctx, "x10");
    if (dstSlot !== SLOT.result32) {
        return;
    }

    const slotBase = contextPtr(ctx, "x24");
    const srcRawBig = readSlotU64(slotBase, srcSlot);
    if (srcRawBig === null) {
        return;
    }

    const src32 = Number(srcRawBig & 0xffffffffn) >>> 0;
    const result32 = rev16_32(src32);
    const dstCell = slotBase.add(dstSlot * 8);
    log(`[metasec+0x${offset.toString(16)}] vm-rev16-to-slot slotBase=${slotBase} srcSlot=${srcSlot} dstSlot=${dstSlot} srcRaw=${hex64(srcRawBig)} src32=${hex32(src32)} result32=${hex32(result32)} dstCell=${dstCell}`);
}

function logVmRor32ToSlot(ctx, offset) {
    const srcSlot = contextU32(ctx, "x8");
    const dstSlot = contextU32(ctx, "x10");
    const rot = contextU32(ctx, "x12") & 31;
    if (dstSlot !== SLOT.result32) {
        return;
    }

    const slotBase = contextPtr(ctx, "x24");
    const srcRawBig = readSlotU64(slotBase, srcSlot);
    if (srcRawBig === null) {
        return;
    }

    const src32 = Number(srcRawBig & 0xffffffffn) >>> 0;
    const result32 = ror32(src32, rot);
    const dstCell = slotBase.add(dstSlot * 8);
    log(`[metasec+0x${offset.toString(16)}] vm-ror32-to-slot slotBase=${slotBase} srcSlot=${srcSlot} dstSlot=${dstSlot} rot=${rot} srcRaw=${hex64(srcRawBig)} src32=${hex32(src32)} result32=${hex32(result32)} dstCell=${dstCell}`);
}

function logVmStore32(ctx, offset) {
    const dstBase = contextPtr(ctx, "x8");
    const srcVal = contextU64(ctx, "x9");
    const off = contextU64(ctx, "x10");
    const insnPtr = contextPtr(ctx, "x0");
    const slotBase = contextPtr(ctx, "x24");

    try {
        const dstSlot = insnPtr.readU8();
        const srcSlot = insnPtr.add(1).readU8();
        const dstOff = insnPtr.add(2).readS16();
        const dstAddress = dstBase.add(Number(off & 0xffffffffn));
        log(`[metasec+0x${offset.toString(16)}] vm-store32 insn=${insnPtr} slotBase=${slotBase} dstSlot=${dstSlot} srcSlot=${srcSlot} off=${dstOff} dstBase=${dstBase} dst=${dstAddress} srcVal=${hex64(srcVal)}`);
        log(`  opcode => ${describeBuffer(insnPtr, 4)}`);
        const dstSlotValue = readSlotU64(slotBase, dstSlot);
        const srcSlotValue = readSlotU64(slotBase, srcSlot);
        log(`  slot[${dstSlot}] => ${dstSlotValue === null ? "<read-failed>" : hex64(dstSlotValue)}`);
        log(`  slot[${srcSlot}] => ${srcSlotValue === null ? "<read-failed>" : hex64(srcSlotValue)}`);
    } catch (e) {
        log(`[metasec+0x${offset.toString(16)}] vm-store32 <decode failed: ${e.message}>`);
    }
}

function installHooks(module) {
    const base = module.base;

    function attach(offset, callback) {
        const address = base.add(offset);
        Interceptor.attach(address, {
            onEnter(args) {
                try {
                    callback.call(this, this.context, offset, args);
                } catch (e) {
                    log(`[metasec+0x${offset.toString(16)}] hook-failed: ${e.stack || e.message}`);
                }
            },
        });
    }

    attach(OFF.componentInsert, function (ctx, offset) {
        const keyRef = readMssdkStringRef(ctx.x1);
        if (keyRef === null || keyRef.text !== "X-Ladon") {
            return;
        }
        markThreadActive();
        const valueRef = readMssdkStringRef(ctx.x2);
        log(`[metasec+0x${offset.toString(16)}] map-insert mapCtx=${ptr(ctx.x0)}`);
        log(`  key   => ${keyRef.desc}`);
        log(`  value => ${valueRef === null ? "null" : valueRef.desc}`);
    });

    attach(OFF.ladonSlot6HashPrecall, function (ctx, offset) {
        markThreadActive();
        log(`[metasec+0x${offset.toString(16)}] ladon-slot6-hash-precall ctx=${ptr(ctx.x19)} slot8Value=${ptr(ctx.x0)} call=sub_269b70`);
        log(`  slot8Obj => ${readLenDataObject(ctx.x0)}`);
    });

    attach(OFF.ladonGlobalSetPrecall, function (ctx, offset) {
        markThreadActive();
        const slot9Value = contextU64(ctx, "x1");
        log(`[metasec+0x${offset.toString(16)}] ladon-global-set-precall ctx=${ptr(ctx.x19)} slot8Value=${ptr(ctx.x0)} slot9Value=${hex64(slot9Value)} call=sub_291e3c`);
    });

    attach(OFF.ladonSlot6SourcePrecall, function (ctx, offset) {
        markThreadActive();
        log(`[metasec+0x${offset.toString(16)}] ladon-slot6-precall ctx=${ptr(ctx.x19)} slot8Value=${ptr(ctx.x0)} call=sub_29fb98`);
    });

    attach(OFF.ladonSlot6SourcePostcall, function (ctx, offset) {
        markThreadActive();
        const ret32 = contextU32(ctx, "x0");
        log(`[metasec+0x${offset.toString(16)}] ladon-slot6-postcall ctx=${ptr(ctx.x19)} ret32=${hex32(ret32)}`);
    });

    attach(OFF.ladonGlobalWordLoad, function (ctx, offset) {
        if (!isThreadActive()) {
            return;
        }
        const globalPtr = ptr(ctx.x0);
        const raw32 = safeReadU32(globalPtr);
        log(`[metasec+0x${offset.toString(16)}] ladon-global-word-load ptr=${globalPtr} raw32=${raw32 === null ? "<read-failed>" : hex32(raw32)}`);
    });

    attach(OFF.vmXor64ToSlot, function (ctx, offset) {
        if (!isThreadActive()) {
            return;
        }
        logVmXor64ToSlot(ctx, offset);
    });

    attach(OFF.vmDerefToSlot, function (ctx, offset) {
        if (!isThreadActive()) {
            return;
        }
        logVmDerefToSlot(ctx, offset, "vm-deref-to-slot");
    });

    attach(OFF.vmDerefToSlot2, function (ctx, offset) {
        if (!isThreadActive()) {
            return;
        }
        logVmDerefToSlot(ctx, offset, "vm-deref-to-slot2");
    });

    attach(OFF.vmXor64CompositeToSlot, function (ctx, offset) {
        if (!isThreadActive()) {
            return;
        }
        logVmXor64CompositeToSlot(ctx, offset);
    });

    attach(OFF.vmRor64ToSlot, function (ctx, offset) {
        if (!isThreadActive()) {
            return;
        }
        logVmRor64ToSlot(ctx, offset);
    });

    attach(OFF.vmLsl32Load, function (ctx, offset) {
        if (!isThreadActive()) {
            return;
        }
        logVmLsl32Load(ctx, offset);
    });

    attach(OFF.vmLsl32Shift, function (ctx, offset) {
        if (!isThreadActive()) {
            return;
        }
        logVmLsl32Shift(ctx, offset);
    });

    attach(OFF.vmRev16ToSlot, function (ctx, offset) {
        if (!isThreadActive()) {
            return;
        }
        logVmRev16ToSlot(ctx, offset);
    });

    attach(OFF.vmRor32ToSlot, function (ctx, offset) {
        if (!isThreadActive()) {
            return;
        }
        logVmRor32ToSlot(ctx, offset);
    });

    attach(OFF.vmStore32, function (ctx, offset) {
        if (!isThreadActive()) {
            return;
        }
        logVmStore32(ctx, offset);
    });

    attach(OFF.ladonBase64Call, function (ctx, offset) {
        if (!isThreadActive()) {
            return;
        }
        const out = ptr(ctx.x0);
        const cap = contextU64(ctx, "x1");
        const outLenPtr = ptr(ctx.x2);
        const arg4 = ptr(ctx.x3);
        const arg5 = contextU64(ctx, "x4");
        const srcObj = ptr(ctx.x19);
        const preview = Number(arg5 > 0x80n ? 0x80n : arg5);
        log(`[metasec+0x${offset.toString(16)}] sub_269dc8 -> base64 out=${out} cap=${hex64(cap)} outLenPtr=${outLenPtr} arg4(src)=${arg4} arg5(len)=${arg5.toString()} srcObj=${srcObj}`);
        log(`  srcObj => ${readLenDataObject(srcObj)}`);
        log(`  arg4-addr=${arg4} ${describeBuffer(arg4, preview)}`);
    });

    log(`[X-Ladon] hooks installed on ${module.name} base=${base}`);
}

function tryInstallHooks() {
    if (STATE.installed) {
        return;
    }

    const module = Process.findModuleByName(TARGET_MODULE);
    if (module === null) {
        return;
    }

    STATE.installed = true;
    STATE.module = module;
    STATE.base = module.base;
    installHooks(module);
}

function watchDlopen() {
    const names = ["android_dlopen_ext", "dlopen"];
    names.forEach((name) => {
        const address = Module.findExportByName(null, name);
        if (address === null) {
            return;
        }

        Interceptor.attach(address, {
            onEnter(args) {
                this.path = args[0].isNull() ? "" : args[0].readCString();
            },
            onLeave(retval) {
                if (STATE.installed) {
                    return;
                }
                if (this.path.indexOf(TARGET_MODULE) !== -1) {
                    setTimeout(tryInstallHooks, 0);
                }
            },
        });
    });
}

setImmediate(() => {
    watchDlopen();
    tryInstallHooks();
    if (!STATE.installed) {
        log(`[X-Ladon] waiting for ${TARGET_MODULE}`);
    }
});
