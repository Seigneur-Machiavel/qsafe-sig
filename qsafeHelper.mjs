// @ts-check
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { BinaryReader } from './binary-writer-reader.mjs';
import { PROTOCOL_VERSIONS, HKDF_INFO_ED25519, HKDF_INFO_MAYO,
		 ED25519_PRIV_SIZE, HEADER_SIZE, VARIANT_BY_ID } from './constants.mjs';

export class QsafeHelper {
    /** Derives ed25519 + mayo seeds from a master seed via HKDF-SHA256.
     * @param {Uint8Array} masterSeed  @param {number} mayoSeedSize */
    static deriveSeeds(masterSeed, mayoSeedSize) {
        const edSeed   = hkdf(sha256, masterSeed, undefined, HKDF_INFO_ED25519, ED25519_PRIV_SIZE);
        const mayoSeed = hkdf(sha256, masterSeed, undefined, HKDF_INFO_MAYO, mayoSeedSize);
        return { edSeed, mayoSeed };
    }

    /** Resolves version + variantId from a signature header. @param {Uint8Array} sig */
    static parseHeader(sig) {
        if (sig.length < HEADER_SIZE) return null;
        const reader    = new BinaryReader(sig);
        const version   = String(reader.readU16BE());
        const variantId = reader.readByte();
        const variant   = VARIANT_BY_ID[variantId];
        const vProto    = PROTOCOL_VERSIONS[version];
        if (!vProto || !variant || !vProto.variants[variant]) return null;
        return { version, variant, desc: vProto.variants[variant] };
    }
}