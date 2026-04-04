// Minimal binary writer/reader for the custom signature format. Not a general-purpose library, just enough for our needs.
export class BinaryWriter {
    cursor = 0;
    view;

    constructor(size) { this.view = new Uint8Array(size); }
    writeByte(b)    { this.view[this.cursor++] = b; }
    writeU16BE(v)   { this.view[this.cursor++] = (v >> 8) & 0xff; this.view[this.cursor++] = v & 0xff; }
    writeBytes(buf) { this.view.set(buf, this.cursor); this.cursor += buf.length; }
    getBytes()      { return this.view; }
}

export class BinaryReader {
    cursor = 0;
    view;
    constructor(buf) { this.view = new Uint8Array(buf); }
    readByte()      { return this.view[this.cursor++]; }
    readU16BE()     { return (this.view[this.cursor++] << 8) | this.view[this.cursor++]; }
    read(n)         { const s = this.cursor; this.cursor += n; return this.view.slice(s, this.cursor); }
}