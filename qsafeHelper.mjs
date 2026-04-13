// @ts-check
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { BinaryReader, BinaryWriter } from './binary-writer-reader.mjs';
import { HKDF_INFO_ED25519, HKDF_INFO_MAYO, DEFAULT_VARIANT, CURRENT_VERSION,
		 ED25519_SIG_SIZE, ED25519_PUB_SIZE, ED25519_PRIV_SIZE,
		 PROTOCOL_VERSIONS, HEADER_SIZE, VARIANT_BY_ID, VARIANT_ID } from './constants.mjs';

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

    /** Derives ed25519 + mayo seeds from a master seed via HKDF-SHA512.
     * @param {Uint8Array} masterSeed  @param {number} mayoSeedSize */
    static deriveSeeds(masterSeed, mayoSeedSize) {
        const edSeed   = hkdf(sha512, masterSeed, undefined, HKDF_INFO_ED25519, ED25519_PRIV_SIZE);
        const mayoSeed = hkdf(sha512, masterSeed, undefined, HKDF_INFO_MAYO, mayoSeedSize);
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

    /** Resolves version + variantId from a hybridKey header.
	 * - Passing the hybridKey header (3 first bytes) will produce the same result.
	 * @param {Uint8Array} hybridKey */
    static parseHeader(hybridKey) {
        if (hybridKey.length < HEADER_SIZE) return null;
        const reader    = new BinaryReader(hybridKey);
        const version   = String(reader.readU16BE());
        const variantId = reader.readByte();
        const variant   = VARIANT_BY_ID[variantId];
        const vProto    = PROTOCOL_VERSIONS[version];
        if (!vProto || !variant || !vProto.variants[variant]) return null;
        return { version, variant, desc: vProto.variants[variant] };
    }

	/** Quick format check for a hybridKey, without parsing the full signature.
	 * @param {Uint8Array} hybridKey
	 * @param {Uint8Array} [hybridSig] Optional: signature associated to the hybridKey. */
	static checkFormat(hybridKey, hybridSig) {
		const h = QsafeHelper.parseHeader(hybridKey);
		if (!h) return false; // invalid header or unknown version/variant
		if (hybridKey.length !== HEADER_SIZE + ED25519_PUB_SIZE + h.desc.pubKeySize) return false;
		if (hybridSig && hybridSig.length !== ED25519_SIG_SIZE + h.desc.sigSize) return false;
		return true;
	}
}