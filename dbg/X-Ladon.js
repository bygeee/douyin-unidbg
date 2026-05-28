/*
 * Frida 17.9.1
 *
 * Usage:
 *   frida -U -f com.ss.android.ugc.aweme -q -l dbg/X-Ladon.js
 *   frida -U -n com.ss.android.ugc.aweme -q -l dbg/X-Ladon.js
 *
 * Focus only on the critical X-Ladon points:
 * 1. sub_269b70(slot8)        -> hash input / hash result
 * 2. sub_291e3c(slot8, slot9) -> low32 written to global word
 * 3. sub_29fb98()             -> low32 read back from global word
 * 4. sub_2b7724(key, value)   -> final X-Ladon inserted into map
 * 5. sub_2590ec(dst, src)     -> slot8 source object copy
 */

"use strict";

const TARGET_MODULE = "libmetasec_ml.so";

const OFF = {
    sub2590ec: 0x2590ec,
    sub269b70: 0x269b70,
    sub291e3c: 0x291e3c,
    sub29fb98: 0x29fb98,
    sub2b7724: 0x2b7724,
};

const RET = {
    sub2590ecFromSlot8Copy: 0x2b7f6c,
    sub269b70FromLadon: 0x2be3f0,
    sub291e3cFromLadon: 0x2be438,
    sub29fb98FromLadon: 0x2be458,
};

const STATE = {
    installed: false,
    base: null,
};

const WATCH_KEYS = new Set([
    "X-Khronos",
    "X-Argus",
    "X-Ladon",
]);

function log(message) {
    console.log(message);
}

function findExportAnywhere(name) {
    if (typeof Module.findGlobalExportByName === "function") {
        const address = Module.findGlobalExportByName(name);
        if (address !== null) {
            return address;
        }
    }

    if (typeof Module.getGlobalExportByName === "function") {
        try {
            return Module.getGlobalExportByName(name);
        } catch (e) {
        }
    }

    if (typeof Module.findExportByName === "function") {
        const address = Module.findExportByName(null, name);
        if (address !== null) {
            return address;
        }
    }

    if (typeof Module.getExportByName === "function") {
        try {
            return Module.getExportByName(null, name);
        } catch (e) {
        }
    }

    for (const module of Process.enumerateModules()) {
        try {
            if (typeof module.findExportByName === "function") {
                const address = module.findExportByName(name);
                if (address !== null) {
                    return address;
                }
            }
            if (typeof module.getExportByName === "function") {
                return module.getExportByName(name);
            }
        } catch (e) {
        }
    }

    return null;
}

function moduleOffsetOf(address) {
    if (STATE.base === null) {
        return null;
    }
    try {
        const absolute = Number.parseInt(ptr(address).toString(), 16);
        const base = Number.parseInt(ptr(STATE.base).toString(), 16);
        return absolute - base;
    } catch (e) {
        return null;
    }
}

function currentTid() {
    try {
        return Process.getCurrentThreadId();
    } catch (e) {
        return -1;
    }
}

function hex32(value) {
    return `0x${(value >>> 0).toString(16)}`;
}

function safeReadByteArray(address, size) {
    if (address === null || ptr(address).isNull() || size <= 0) {
        return null;
    }
    try {
        return Memory.readByteArray(ptr(address), size);
    } catch (e) {
        try {
            if (typeof ptr(address).readVolatile === "function") {
                return ptr(address).readVolatile(size);
            }
        } catch (e2) {
        }
        return null;
    }
}

function safeReadUtf8String(address, size) {
    if (address === null || ptr(address).isNull() || size <= 0) {
        return null;
    }
    try {
        return ptr(address).readUtf8String(size);
    } catch (e) {
        try {
            return ptr(address).readCString();
        } catch (e2) {
            return null;
        }
    }
}

function bytesToHex(bytes) {
    if (bytes === null) {
        return "<read-failed>";
    }
    const view = new Uint8Array(bytes);
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
    const view = new Uint8Array(bytes);
    let out = "";
    for (let i = 0; i < view.length; i += 1) {
        const ch = view[i];
        if (ch >= 0x20 && ch <= 0x7e) {
            out += String.fromCharCode(ch);
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

function describeRange(address) {
    if (address === null || ptr(address).isNull()) {
        return "range=<null>";
    }
    try {
        const range = Process.findRangeByAddress(ptr(address));
        if (range === null) {
            return "range=<unmapped>";
        }
        return `range=${range.base}-${range.base.add(range.size)} prot=${range.protection}`;
    } catch (e) {
        return `range=<error:${e.message}>`;
    }
}

function isAsciiDigits(text) {
    return typeof text === "string" && /^[0-9]+$/.test(text);
}

function readLenDataObject(address) {
    if (address === null || ptr(address).isNull()) {
        return "null";
    }
    try {
        const obj = ptr(address);
        const len = obj.add(0xc).readU32() >>> 0;
        const data = obj.add(0x10).readPointer();
        const preview = Math.min(len, 0x80);
        const utf8 = safeReadUtf8String(data, preview);
        const extra = utf8 === null ? "" : ` utf8=${JSON.stringify(utf8)}`;
        return `obj=${obj} len=${len} data=${data} ${describeRange(data)} ${describeBuffer(data, preview)}${extra}`;
    } catch (e) {
        return `obj=${ptr(address)} <decode failed: ${e.message}>`;
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
        const utf8 = safeReadUtf8String(data, Math.min(len, 0x100));
        return {
            text,
            desc: `ref=${ref} alloc=${alloc} len=${len} data=${data} ${describeRange(data)} ${describeBuffer(data, Math.min(len, 0x100))}${utf8 === null ? "" : ` utf8=${JSON.stringify(utf8)}`}`,
        };
    } catch (e) {
        return {
            text: null,
            desc: `ref=${ptr(address)} <decode failed: ${e.message}>`,
        };
    }
}

function attachSafe(module, label, offset, callbacks) {
    const address = module.base.add(offset);
    try {
        Interceptor.attach(address, callbacks);
        log(`[X-Ladon] attached ${label} at ${address} (metasec+0x${offset.toString(16)})`);
    } catch (e) {
        log(`[X-Ladon] skip ${label} at ${address} (metasec+0x${offset.toString(16)}): ${e.message}`);
    }
}

function installHooks(module) {
    attachSafe(module, "sub_2590ec", OFF.sub2590ec, {
        onEnter(args) {
            const returnOffset = moduleOffsetOf(this.returnAddress);
            if (returnOffset !== RET.sub2590ecFromSlot8Copy) {
                this.skip = true;
                return;
            }

            this.skip = true;
            this.dstObj = ptr(args[0]);
            this.srcObj = ptr(args[1]);

            try {
                const len = this.srcObj.add(0xc).readU32() >>> 0;
                const data = this.srcObj.add(0x10).readPointer();
                const preview = Math.min(len, 0x40);
                const utf8 = safeReadUtf8String(data, preview);
                if (len !== 10 || !isAsciiDigits(utf8)) {
                    return;
                }

                this.skip = false;
                this.tid = currentTid();
                log(`[tid=${this.tid}] [metasec+0x${RET.sub2590ecFromSlot8Copy.toString(16)}] ladon-slot8-copy-pre dstObj=${this.dstObj} srcObj=${this.srcObj}`);
                log(`  src(before) => ${readLenDataObject(this.srcObj)}`);
            } catch (e) {
            }
        },
        onLeave(retval) {
            if (this.skip) {
                return;
            }
            log(`[tid=${this.tid}] [metasec+0x${RET.sub2590ecFromSlot8Copy.toString(16)}] ladon-slot8-copy-post retval=${ptr(retval)}`);
            log(`  dst(after) => ${readLenDataObject(this.dstObj)}`);
        },
    });

    attachSafe(module, "sub_269b70", OFF.sub269b70, {
        onEnter(args) {
            const returnOffset = moduleOffsetOf(this.returnAddress);
            if (returnOffset !== RET.sub269b70FromLadon) {
                this.skip = true;
                return;
            }

            this.skip = false;
            this.slot8 = ptr(args[0]);
            this.tid = currentTid();
            log(`[tid=${this.tid}] [metasec+0x${RET.sub269b70FromLadon.toString(16)}] ladon-slot6-hash-precall slot8Value=${this.slot8} call=sub_269b70`);
            log(`  slot8Obj => ${readLenDataObject(this.slot8)}`);
        },
        onLeave(retval) {
            if (this.skip) {
                return;
            }
            log(`[tid=${this.tid}] [metasec+0x${RET.sub269b70FromLadon.toString(16)}] ladon-slot6-hash-ret ret64=${ptr(retval)}`);
        },
    });

    attachSafe(module, "sub_291e3c", OFF.sub291e3c, {
        onEnter(args) {
            const returnOffset = moduleOffsetOf(this.returnAddress);
            if (returnOffset !== RET.sub291e3cFromLadon) {
                return;
            }

            const slot8Value = ptr(args[0]);
            const slot9Low32 = ptr(args[1]).toUInt32();
            log(`[tid=${currentTid()}] [metasec+0x${RET.sub291e3cFromLadon.toString(16)}] ladon-global-set-precall slot8Value=${slot8Value} slot9Low32=${hex32(slot9Low32)} call=sub_291e3c`);
        },
    });

    attachSafe(module, "sub_29fb98", OFF.sub29fb98, {
        onEnter(args) {
            const returnOffset = moduleOffsetOf(this.returnAddress);
            if (returnOffset !== RET.sub29fb98FromLadon) {
                this.skip = true;
                return;
            }

            this.skip = false;
            this.ctx = ptr(this.context.x19);
            this.slot8 = ptr(this.context.x0);
            this.tid = currentTid();
            log(`[tid=${this.tid}] [metasec+0x${RET.sub29fb98FromLadon.toString(16)}] ladon-slot6-precall ctx=${this.ctx} slot8Value=${this.slot8} call=sub_29fb98`);
        },
        onLeave(retval) {
            if (this.skip) {
                return;
            }
            const raw32 = ptr(retval).toUInt32();
            log(`[tid=${this.tid}] [metasec+0x${OFF.sub29fb98.toString(16)}] ladon-global-word-load raw32=${hex32(raw32)}`);
            log(`[tid=${this.tid}] [metasec+0x${RET.sub29fb98FromLadon.toString(16)}] ladon-slot6-postcall ctx=${this.ctx} ret32=${hex32(raw32)}`);
        },
    });

    attachSafe(module, "sub_2b7724", OFF.sub2b7724, {
        onEnter(args) {
            const keyRef = readMssdkStringRef(args[1]);
            if (keyRef === null || keyRef.text === null || !WATCH_KEYS.has(keyRef.text)) {
                return;
            }

            const valueRef = readMssdkStringRef(args[2]);
            log(`[tid=${currentTid()}] [metasec+0x${OFF.sub2b7724.toString(16)}] map-insert mapCtx=${ptr(args[0])}`);
            log(`  key   => ${keyRef.desc}`);
            log(`  value => ${valueRef === null ? "null" : valueRef.desc}`);
        },
    });

    log(`[X-Ladon] hooks installed on ${module.name} base=${module.base}`);
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
    STATE.base = module.base;
    installHooks(module);
}

function watchDlopen() {
    ["android_dlopen_ext", "dlopen"].forEach((name) => {
        const address = findExportAnywhere(name);
        if (address === null) {
            return;
        }

        Interceptor.attach(address, {
            onEnter(args) {
                this.path = args[0].isNull() ? "" : args[0].readCString();
            },
            onLeave(retval) {
                if (!STATE.installed && this.path.indexOf(TARGET_MODULE) !== -1) {
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
