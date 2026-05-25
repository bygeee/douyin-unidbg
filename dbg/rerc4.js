const crypto = require("crypto");

function normalizeHex(hex) {
    return hex.replace(/[^0-9a-fA-F]/g, "").toLowerCase();
}

function hexToBytes(hex) {
    hex = normalizeHex(hex);
    if (hex.length % 2 !== 0) {
        throw new Error("hex length must be even");
    }
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
}

function bytesToHex(bytes) {
    let out = "";
    for (const b of bytes) {
        out += b.toString(16).padStart(2, "0");
    }
    return out;
}

function reverseByte(x) {
    let r = 0;
    for (let i = 0; i < 8; i++) {
        r = (r << 1) | ((x >>> i) & 1);
    }
    return r & 0xff;
}

function swapNibble(x) {
    return (((x >>> 4) & 0x0f) | ((x & 0x0f) << 4)) & 0xff;
}

function md5Hex(text) {
    return crypto.createHash("md5").update(text, "utf8").digest("hex");
}

function u32ToLEBytes(value) {
    return new Uint8Array([
        value & 0xff,
        (value >>> 8) & 0xff,
        (value >>> 16) & 0xff,
        (value >>> 24) & 0xff,
    ]);
}

function u32ToBEBytes(value) {
    return new Uint8Array([
        (value >>> 24) & 0xff,
        (value >>> 16) & 0xff,
        (value >>> 8) & 0xff,
        value & 0xff,
    ]);
}

function queryFromUrl(url) {
    const index = url.indexOf("?");
    return index >= 0 ? url.slice(index + 1) : url;
}

function buildInput20(queryString, xSsStubHex, versionWord, khronos) {
    const queryMd5 = hexToBytes(md5Hex(queryString));
    const stub = hexToBytes(xSsStubHex);
    if (queryMd5.length !== 16) {
        throw new Error("query md5 must be 16 bytes");
    }
    if (stub.length !== 16) {
        throw new Error("x-ss-stub must be 16 bytes");
    }

    const out = new Uint8Array(20);
    out.set(queryMd5.subarray(0, 4), 0);
    out.set(stub.subarray(0, 4), 4);
    out.set(u32ToLEBytes(versionWord), 12);
    out.set(u32ToBEBytes(khronos), 16);
    return out;
}

function buildKey(seedLo, seedHi, arg2) {
    // 0x2c21a8 看到的 4a0016d200000080 只是 init-loop 早期快照。
    // 后续 0x2c21c0 会把中间 2 字节补成 47 6c，真正进入 KSA 时生效的是：
    // [0x4a, arg2_lo, 0x16, outBuf_hi, 0x47, 0x6c, arg2_hi, outBuf_lo]
    // 例如 outBuf=0x130ed280, arg2=0x0000 => 4a0016d2476c0080
    return new Uint8Array([
        0x4a,
        arg2 & 0xff,
        0x16,
        seedHi & 0xff,
        0x47,
        0x6c,
        (arg2 >>> 8) & 0xff,
        seedLo & 0xff,
    ]);
}

function seedFromOutBuf(outBufAddr) {
    return {
        seedLo: outBufAddr & 0xff,
        seedHi: (outBufAddr >>> 8) & 0xff,
    };
}

function gorgonRaw(inputBytes, seedLo, seedHi, arg2 = 0) {
    const len = inputBytes.length;
    if (len !== 20) {
        throw new Error("this version expects 20-byte input");
    }

    const out = new Uint8Array(len + 6);

    // final header layout
    out[0] = 0x84;
    out[1] = 0x04;
    out[2] = seedLo & 0xff;
    out[3] = seedHi & 0xff;
    out[4] = arg2 & 0xff;
    out[5] = (arg2 >>> 8) & 0xff;

    // copy input to out[6..]
    out.set(inputBytes, 6);

    const key = buildKey(seedLo, seedHi, arg2);

    // init sbox
    const s = new Uint8Array(256);
    for (let i = 0; i < 256; i++) {
        s[i] = i;
    }

    // KSA-like stage
    // note: this is NOT normal RC4 swap
    let j = 0;
    for (let i = 0; i < 256; i++) {
        j = (j + s[i] + key[i & 7]) & 0xff;
        const v = s[j];
        s[i] = v;
        s[j] = v;
    }

    // PRGA-like xor stage
    // also NOT normal RC4 swap
    let x = 0;
    let y = 0;
    for (let i = 0; i < len; i++) {
        x = (x + 1) & 0xff;
        y = (y + s[x]) & 0xff;
        const v = s[y];
        s[x] = v;
        s[y] = v;
        out[6 + i] ^= s[(v + v) & 0xff];
    }

    // post-process stage
    for (let i = 0; i < len; i++) {
        let t = swapNibble(out[6 + i]);

        if (i + 1 < len) {
            t ^= out[6 + i + 1];
        } else if (i !== 0) {
            t ^= out[6];
        }
        out[6 + i] = (len ^ ((~reverseByte(t)) & 0xff)) & 0xff;
    }

    return out;
}

function makeXGorgon(input20Hex, seedLo, seedHi, arg2 = 0) {
    const input = hexToBytes(input20Hex);
    return bytesToHex(gorgonRaw(input, seedLo, seedHi, arg2));
}
//url的?后的内容
const url = "https://saveu5-normal-lf.zijieapi.com/api/plugin/config/v2/?soc_platform=oriole&klink_egdi=AALoRZcdV2svBgFaig7nMvIYzGfyJJtBq-w7jRYLnccv42XROIeGXNRW&iid=239074334481508&device_id=3352861784673370&ac=wifi&channel=gray_38700100&aid=1128&app_name=aweme&version_code=380700&version_name=38.7.0&device_platform=android&os=android&ssmix=a&device_type=AOSP+on+Oriole&device_brand=Android&language=zh&os_api=33&os_version=13&manifest_version_code=380700&resolution=1080*2146&dpi=420&update_version_code=38700100&_rticket=1779160424642&package=com.ss.android.ugc.aweme&first_launch_timestamp=1778564855&last_deeplink_update_version_code=0&cpu_support64=true&host_abi=arm64-v8a&is_guest_mode=0&app_type=normal&minor_status=0&appTheme=light&is_preinstall=0&need_personal_recommend=1&is_android_pad=0&is_android_fold=0&ts=1779160424&cdid=eb69b3a3-2366-4a79-bda1-00397ecd44b4";
const query = queryFromUrl(url);
//另一个cookie值  x-ss-stub
const xSsStub = "ADC998A471339FB545EB10906AC76CF3";

const versionWord = 0x040a0000; //版本环境

const khronos = 1779160424;//时间戳

const input = buildInput20(query, xSsStub, versionWord, khronos);

// const outBufAddr = 0x130ed280;
// const { seedLo, seedHi } = seedFromOutBuf(outBufAddr);
//根据堆内存的低16位地址
const seedLo=128
const seedHi=210

const arg2 = 0x0000;

console.log("query-md5 =", md5Hex(query));
console.log("x-ss-stub =", xSsStub.toLowerCase());
console.log("input20    =", bytesToHex(input));
console.log("x-gorgon   =", bytesToHex(gorgonRaw(input, seedLo, seedHi, arg2)));
