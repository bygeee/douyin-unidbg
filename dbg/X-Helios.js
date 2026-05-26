const crypto = require("crypto");

const MASK64 = (1n << 64n) - 1n;

function normalizeHex(hex) {
    return String(hex).replace(/[^0-9a-fA-F]/g, "").toLowerCase();
}

function hexToBytes(hex) {
    const normalized = normalizeHex(hex);
    if (normalized.length % 2 !== 0) {
        throw new Error(`hex length must be even, got ${normalized.length}`);
    }
    return Buffer.from(normalized, "hex");
}

function bytesToHex(bytes) {
    return Buffer.from(bytes).toString("hex");
}

function md5Hex(text) {
    return crypto.createHash("md5").update(String(text), "utf8").digest("hex");
}

function md5BytesHex(bytes) {
    return crypto.createHash("md5").update(Buffer.from(bytes)).digest("hex");
}

function queryFromUrl(url) {
    const index = url.indexOf("?");
    return index >= 0 ? url.slice(index + 1) : url;
}

function queryParam(input, key) {
    const params = new URLSearchParams(queryFromUrl(String(input)));
    return params.get(String(key));
}

function reverseByte(value) {
    let result = 0;
    for (let bit = 0; bit < 8; bit += 1) {
        result = (result << 1) | ((value >>> bit) & 1);
    }
    return result & 0xff;
}

function swapNibble(value) {
    return (((value >>> 4) & 0x0f) | ((value & 0x0f) << 4)) & 0xff;
}

function u32ToLEBytes(value) {
    return Buffer.from([
        value & 0xff,
        (value >>> 8) & 0xff,
        (value >>> 16) & 0xff,
        (value >>> 24) & 0xff,
    ]);
}

function u32ToBEBytes(value) {
    return Buffer.from([
        (value >>> 24) & 0xff,
        (value >>> 16) & 0xff,
        (value >>> 8) & 0xff,
        value & 0xff,
    ]);
}

function ror64(value, bits) {
    const shift = BigInt(bits);
    return ((value >> shift) | (value << (64n - shift))) & MASK64;
}

function rol64(value, bits) {
    const shift = BigInt(bits);
    return ((value << shift) | (value >> (64n - shift))) & MASK64;
}

function readU64LE(bytes, offset) {
    let value = 0n;
    for (let i = 7; i >= 0; i -= 1) {
        value = (value << 8n) | BigInt(bytes[offset + i]);
    }
    return value;
}

function writeU64LE(value, output, offset) {
    let current = value & MASK64;
    for (let i = 0; i < 8; i += 1) {
        output[offset + i] = Number(current & 0xffn);
        current >>= 8n;
    }
}

function pkcs7Pad(input, blockSize) {
    const source = Buffer.from(input);
    if (!Number.isInteger(blockSize) || blockSize <= 0 || blockSize > 0xff) {
        throw new Error(`invalid PKCS#7 block size: ${blockSize}`);
    }
    const remainder = source.length % blockSize;
    const pad = remainder === 0 ? blockSize : blockSize - remainder;
    const output = Buffer.alloc(source.length + pad, pad);
    source.copy(output, 0);
    return output;
}

function expandSpeck128256Key(keyBytes) {
    const key = Buffer.from(keyBytes);
    if (key.length !== 32) {
        throw new Error(`speck128/256 key must be 32 bytes, got ${key.length}`);
    }

    let k = readU64LE(key, 0);
    const l = [
        readU64LE(key, 8),
        readU64LE(key, 16),
        readU64LE(key, 24),
    ];
    const roundKeys = [k];

    for (let round = 0; round < 33; round += 1) {
        const nextL = ((ror64(l[round], 8) + k) & MASK64) ^ BigInt(round);
        const nextK = rol64(k, 3) ^ nextL;
        l.push(nextL);
        roundKeys.push(nextK);
        k = nextK;
    }

    return roundKeys;
}

function encryptSpeck128256Block(blockBytes, roundKeys) {
    const block = Buffer.from(blockBytes);
    if (block.length !== 16) {
        throw new Error(`speck128 block must be 16 bytes, got ${block.length}`);
    }
    if (roundKeys.length !== 34) {
        throw new Error(`speck128/256 requires 34 round keys, got ${roundKeys.length}`);
    }

    let y = readU64LE(block, 0);
    let x = readU64LE(block, 8);

    for (let round = 0; round < 34; round += 1) {
        x = ((ror64(x, 8) + y) & MASK64) ^ roundKeys[round];
        y = rol64(y, 3) ^ x;
    }

    const output = Buffer.alloc(16);
    writeU64LE(y, output, 0);
    writeU64LE(x, output, 8);
    return output;
}

function encryptSpeck128256EcbPkcs7(inputBytes, keyBytes) {
    const padded = pkcs7Pad(inputBytes, 16);
    const roundKeys = expandSpeck128256Key(keyBytes);
    const output = Buffer.alloc(padded.length);

    for (let offset = 0; offset < padded.length; offset += 16) {
        const block = encryptSpeck128256Block(padded.subarray(offset, offset + 16), roundKeys);
        block.copy(output, offset);
    }

    return output;
}

function heliosBody32(message26, key32) {
    const messageBytes = Buffer.isBuffer(message26) ? Buffer.from(message26) : Buffer.from(String(message26), "utf8");
    const keyBytes = Buffer.isBuffer(key32) ? Buffer.from(key32) : Buffer.from(String(key32), "utf8");
    return encryptSpeck128256EcbPkcs7(messageBytes, keyBytes);
}

function deriveHeliosKey32(prefix4Hex, aid) {
    const prefix4 = Buffer.isBuffer(prefix4Hex) ? Buffer.from(prefix4Hex) : hexToBytes(prefix4Hex);
    if (prefix4.length !== 4) {
        throw new Error(`prefix4 must be 4 bytes, got ${prefix4.length}`);
    }
    if (aid === undefined || aid === null || String(aid).length === 0) {
        throw new Error("aid is required to derive key32");
    }
    return md5BytesHex(Buffer.concat([prefix4, Buffer.from(String(aid), "utf8")]));
}

function buildHeliosValue(prefix4Hex, message26, key32) {
    const prefix4 = hexToBytes(prefix4Hex);
    if (prefix4.length !== 4) {
        throw new Error(`prefix4 must be 4 bytes, got ${prefix4.length}`);
    }
    const body32 = heliosBody32(message26, key32);
    const binary = Buffer.concat([prefix4, body32]);
    return {
        prefix4,
        body32,
        binary,
        base64: binary.toString("base64"),
    };
}

function buildInput20(queryString, xSsStubHex, versionWord, khronos) {
    const queryMd5 = hexToBytes(md5Hex(queryString));
    const xSsStub = hexToBytes(xSsStubHex);
    if (queryMd5.length !== 16) {
        throw new Error(`query-md5 must be 16 bytes, got ${queryMd5.length}`);
    }
    if (xSsStub.length !== 16) {
        throw new Error(`x-ss-stub must be 16 bytes, got ${xSsStub.length}`);
    }

    const output = Buffer.alloc(20);
    output.set(queryMd5.subarray(0, 4), 0);
    output.set(xSsStub.subarray(0, 4), 4);
    output.set(u32ToLEBytes(versionWord >>> 0), 12);
    output.set(u32ToBEBytes(khronos >>> 0), 16);
    return output;
}

function buildGorgonKey(outBufLo, outBufHi, arg2 = 0) {
    return Buffer.from([
        0x4a,
        arg2 & 0xff,
        0x16,
        outBufHi & 0xff,
        0x47,
        0x6c,
        (arg2 >>> 8) & 0xff,
        outBufLo & 0xff,
    ]);
}

function seedFromOutBuf(outBufAddr) {
    return {
        seedLo: outBufAddr & 0xff,
        seedHi: (outBufAddr >>> 8) & 0xff,
    };
}

function gorgonRaw(input20Bytes, outBufLo, outBufHi, arg2 = 0) {
    const input = Buffer.from(input20Bytes);
    if (input.length !== 20) {
        throw new Error(`sub_2c20d4 expects 20-byte input, got ${input.length}`);
    }

    const output = Buffer.alloc(input.length + 6);
    output[0] = 0x84;
    output[1] = 0x04;
    output[2] = outBufLo & 0xff;
    output[3] = outBufHi & 0xff;
    output[4] = arg2 & 0xff;
    output[5] = (arg2 >>> 8) & 0xff;
    input.copy(output, 6);

    const sbox = Buffer.alloc(256);
    for (let i = 0; i < 256; i += 1) {
        sbox[i] = i;
    }

    const key = buildGorgonKey(outBufLo, outBufHi, arg2);

    let j = 0;
    for (let i = 0; i < 256; i += 1) {
        j = (j + sbox[i] + key[i & 7]) & 0xff;
        const value = sbox[j];
        sbox[i] = value;
        sbox[j] = value;
    }

    let x = 0;
    let y = 0;
    for (let i = 0; i < input.length; i += 1) {
        x = (x + 1) & 0xff;
        y = (y + sbox[x]) & 0xff;
        const value = sbox[y];
        sbox[x] = value;
        sbox[y] = value;
        output[6 + i] ^= sbox[(value + value) & 0xff];
    }

    for (let i = 0; i < input.length; i += 1) {
        let value = swapNibble(output[6 + i]);
        if (i + 1 < input.length) {
            value ^= output[6 + i + 1];
        } else if (i !== 0) {
            value ^= output[6];
        }
        output[6 + i] = (input.length ^ ((~reverseByte(value)) & 0xff)) & 0xff;
    }

    return output;
}

function makeXGorgon(input20Hex, outBufLo, outBufHi, arg2 = 0) {
    return bytesToHex(gorgonRaw(hexToBytes(input20Hex), outBufLo, outBufHi, arg2));
}

function buildXGorgonValue(queryString, xSsStubHex, versionWord, khronos, outBufLo, outBufHi, arg2 = 0) {
    const queryMd5 = md5Hex(queryString);
    const input20 = buildInput20(queryString, xSsStubHex, versionWord, khronos);
    const xGorgon = gorgonRaw(input20, outBufLo, outBufHi, arg2);
    return {
        queryMd5,
        xSsStub: normalizeHex(xSsStubHex),
        input20,
        xGorgon,
    };
}

function buildHeliosDebug(options) {
    const {
        url,
        query,
        aid,
        xSsStubHex,
        versionWord,
        khronos,
        outBufLo,
        outBufHi,
        arg2 = 0,
        prefix4Hex,
        message26,
        key32,
    } = options;

    const queryString = query ?? queryFromUrl(url);
    const resolvedAid = aid ?? (url ? queryParam(url, "aid") : null);
    const resolvedKey32 = key32 ?? deriveHeliosKey32(prefix4Hex, resolvedAid);
    const gorgon = buildXGorgonValue(
        queryString,
        xSsStubHex,
        versionWord,
        khronos,
        outBufLo,
        outBufHi,
        arg2,
    );
    const helios = buildHeliosValue(prefix4Hex, message26, resolvedKey32);

    return {
        aid: resolvedAid,
        query: queryString,
        queryMd5: gorgon.queryMd5,
        xSsStub: gorgon.xSsStub,
        input20: gorgon.input20,
        xGorgon: gorgon.xGorgon,
        key32: resolvedKey32,
        prefix4: helios.prefix4,
        body32: helios.body32,
        binary: helios.binary,
        heliosBase64: helios.base64,
    };
}

module.exports = {
    buildGorgonKey,
    buildHeliosDebug,
    buildHeliosValue,
    buildInput20,
    buildXGorgonValue,
    bytesToHex,
    deriveHeliosKey32,
    encryptSpeck128256Block,
    encryptSpeck128256EcbPkcs7,
    expandSpeck128256Key,
    gorgonRaw,
    heliosBody32,
    hexToBytes,
    makeXGorgon,
    md5BytesHex,
    md5Hex,
    normalizeHex,
    pkcs7Pad,
    queryParam,
    queryFromUrl,
    seedFromOutBuf,
};

if (require.main === module) {
    const sample = buildHeliosDebug({
        url: "https://saveu5-normal-lf.zijieapi.com/api/plugin/config/v2/?soc_platform=oriole&klink_egdi=AALoRZcdV2svBgFaig7nMvIYzGfyJJtBq-w7jRYLnccv42XROIeGXNRW&iid=239074334481508&device_id=3352861784673370&ac=wifi&channel=gray_38700100&aid=1128&app_name=aweme&version_code=380700&version_name=38.7.0&device_platform=android&os=android&ssmix=a&device_type=AOSP+on+Oriole&device_brand=Android&language=zh&os_api=33&os_version=13&manifest_version_code=380700&resolution=1080*2146&dpi=420&update_version_code=38700100&_rticket=1779160424642&package=com.ss.android.ugc.aweme&first_launch_timestamp=1778564855&last_deeplink_update_version_code=0&cpu_support64=true&host_abi=arm64-v8a&is_guest_mode=0&app_type=normal&minor_status=0&appTheme=light&is_preinstall=0&need_personal_recommend=1&is_android_pad=0&is_android_fold=0&ts=1779160424&cdid=eb69b3a3-2366-4a79-bda1-00397ecd44b4",
        xSsStubHex: "ADC998A471339FB545EB10906AC76CF3",
        versionWord: 0x040a0000,
        khronos: 1779160424,
        outBufLo: 0x80,
        outBufHi: 0xd2,
        arg2: 0x0000,
        prefix4Hex: "fa3b5647",
        message26: "1779160424-1611921764-3019",
    });

    console.log("query-md5 =", sample.queryMd5);
    console.log("x-ss-stub =", sample.xSsStub);
    console.log("input20    =", bytesToHex(sample.input20));
    console.log("x-gorgon   =", bytesToHex(sample.xGorgon));
    console.log("key32      =", sample.key32);
    console.log("body32     =", bytesToHex(sample.body32));
    console.log("helios     =", sample.heliosBase64);
}
