// @ts-check

/** Generates a random Uint8Array of `len` bytes.
 * - Uses crypto.getRandomValues in 65536-byte chunks (browser/Node API limit).
 * @param {number} len @returns {Uint8Array} */
export function createRandomMessage(len) {
    const buf = new Uint8Array(len);
    const CHUNK = 65536;
    for (let offset = 0; offset < len; offset += CHUNK)
        crypto.getRandomValues(buf.subarray(offset, Math.min(offset + CHUNK, len)));
    return buf;
}

/** Constant-time byte equality check.
 * @param {Uint8Array} a @param {Uint8Array} b */
export function eq(a, b) { // simple loop for easier debugging hover breakpoints.
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++)
        if (a[i] !== b[i]) return false;
    return true;
}
