// @ts-check
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { BinaryReader, BinaryWriter } from './binary-writer-reader.mjs';
import { PROTOCOL_VERSIONS, HKDF_INFO_ED25519, HKDF_INFO_MAYO, DEFAULT_VARIANT, CURRENT_VERSION,
		 ED25519_SIG_SIZE, ED25519_PRIV_SIZE, HEADER_SIZE, VARIANT_BY_ID, VARIANT_ID } from './constants.mjs';

export class QsafeHelper {
	/** Retrieves the descriptor for a given protocol version and variant, throwing if unknown.
	 * @param {'mayo1' | 'mayo2'} [variant] defaults to DEFAULT_VARIANT
	 * @param {string} [version] defaults to CURRENT_VERSION */
	static getVariantDescriptor(variant = DEFAULT_VARIANT, version = CURRENT_VERSION) {
		const vProto = PROTOCOL_VERSIONS[version];
		if (!vProto) throw new Error(`Unknown protocol version: ${version}`);
		const desc = vProto.variants[variant];
		if (!desc) throw new Error(`Unknown variant '${variant}' for protocol version ${version}`);
		return desc;
	}

    /** Derives ed25519 + mayo seeds from a master seed via HKDF-SHA256.
     * @param {Uint8Array} masterSeed  @param {number} mayoSeedSize */
    static deriveSeeds(masterSeed, mayoSeedSize) {
        const edSeed   = hkdf(sha256, masterSeed, undefined, HKDF_INFO_ED25519, ED25519_PRIV_SIZE);
        const mayoSeed = hkdf(sha256, masterSeed, undefined, HKDF_INFO_MAYO, mayoSeedSize);
        return { edSeed, mayoSeed };
    }

	/** Build a QsafeSigner header for the given version and variant: <version(u16 BE) + variantId(u8)>
	 * - Returned as a Uint8Array or write directly at cursor position if a BinaryWriter is provided.
	 * @param {'mayo1' | 'mayo2'} [variant] defaults to DEFAULT_VARIANT
	 * @param {string} [version] defaults to CURRENT_VERSION
	 * @param {BinaryWriter} [writer] - Optional pre-allocated writer */
	static buildHeader(variant = DEFAULT_VARIANT, version = CURRENT_VERSION, writer) {
		const w = writer || new BinaryWriter(HEADER_SIZE);
		w.writeU16BE(Number(version));
        w.writeByte(VARIANT_ID[variant]);
		if (!writer) return w.getBytes();
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

	/** Checks that a signature buffer has a valid header and correct byte length.
     * - Zero crypto — safe to call as a fast pre-filter. @param {Uint8Array} signature */
    static checkSignatureFormat(signature) {
        const h = QsafeHelper.parseHeader(signature);
        if (h) return signature.length === HEADER_SIZE + ED25519_SIG_SIZE + h.desc.sigSize;
        else return false;
    }
}