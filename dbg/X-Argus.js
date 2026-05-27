function normalizeU32(value) {
    if (typeof value === "number") {
        if (!Number.isFinite(value) || !Number.isInteger(value)) {
            throw new Error(`khronos must be an integer, got ${value}`);
        }
        return value >>> 0;
    }

    if (typeof value === "bigint") {
        if (value < 0n || value > 0xffffffffn) {
            throw new Error(`khronos bigint out of range: ${value}`);
        }
        return Number(value);
    }

    const text = String(value).trim().toLowerCase();
    if (!text) {
        throw new Error("khronos is required");
    }

    let parsed;
    if (text.startsWith("0x")) {
        parsed = Number.parseInt(text.slice(2), 16);
    } else {
        parsed = Number.parseInt(text, 10);
    }
    if (!Number.isFinite(parsed) || !Number.isInteger(parsed) || parsed < 0 || parsed > 0xffffffff) {
        throw new Error(`invalid u32 value: ${value}`);
    }
    return parsed >>> 0;
}

function u32ToLEBytes(value) {
    const v = normalizeU32(value);
    return Buffer.from([
        v & 0xff,
        (v >>> 8) & 0xff,
        (v >>> 16) & 0xff,
        (v >>> 24) & 0xff,
    ]);
}

function leBytesToU32(bytes) {
    const input = Buffer.from(bytes);
    if (input.length !== 4) {
        throw new Error(`X-Argus raw bytes must be 4 bytes, got ${input.length}`);
    }
    return (
        input[0] |
        (input[1] << 8) |
        (input[2] << 16) |
        (input[3] << 24)
    ) >>> 0;
}

function bytesToHex(bytes) {
    return Buffer.from(bytes).toString("hex");
}

function buildXArgusBytes(khronos) {
    return u32ToLEBytes(khronos);
}

function buildXArgusValue(khronos) {
    return buildXArgusBytes(khronos).toString("base64");
}

function buildXArgusDebug(khronos) {
    const normalized = normalizeU32(khronos);
    const raw = buildXArgusBytes(normalized);
    return {
        khronos: normalized,
        khronosHex: `0x${normalized.toString(16)}`,
        raw,
        rawHex: bytesToHex(raw),
        xArgus: raw.toString("base64"),
    };
}

function decodeXArgusValue(xArgus) {
    const raw = Buffer.from(String(xArgus).trim(), "base64");
    if (raw.length !== 4) {
        throw new Error(`decoded X-Argus must be 4 bytes, got ${raw.length}`);
    }
    const khronos = leBytesToU32(raw);
    return {
        xArgus: String(xArgus).trim(),
        raw,
        rawHex: bytesToHex(raw),
        khronos,
        khronosHex: `0x${khronos.toString(16)}`,
    };
}

module.exports = {
    buildXArgusBytes,
    buildXArgusDebug,
    buildXArgusValue,
    bytesToHex,
    decodeXArgusValue,
    leBytesToU32,
    normalizeU32,
    u32ToLEBytes,
};

if (require.main === module) {
    const sampleKhronos = process.argv[2] ?? "1779160424";
    const sample = buildXArgusDebug(sampleKhronos);

    console.log("khronos =", sample.khronos);
    console.log("khronosHex =", sample.khronosHex);
    console.log("rawHex =", sample.rawHex);
    console.log("xArgus =", sample.xArgus);
}
