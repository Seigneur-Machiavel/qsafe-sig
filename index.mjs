// @ts-check
import { QsafeHelper } from './qsafeHelper.mjs';
import { ed25519 } from '@noble/curves/ed25519.js';
import { BinaryWriter, BinaryReader } from './binary-writer-reader.mjs';
import { PROTOCOL_VERSIONS, CURRENT_VERSION, DEFAULT_VARIANT, AVAILABLE_VERSIONS,
		 ED25519_PRIV_SIZE, ED25519_PUB_SIZE, ED25519_SIG_SIZE,
		 HEADER_SIZE, VARIANT_ID } from './constants.mjs';

export { ed25519, PROTOCOL_VERSIONS, CURRENT_VERSION, AVAILABLE_VERSIONS };

/** 
 * @typedef {{ publicKey: Uint8Array, secretKey: Uint8Array }} Keypair
 * @typedef {import('@pinkparrot/qsafe-mayo-wasm').MayoSigner} MayoSigner */

export class QsafeSigner {
    // Shared stateless instances for verify() — one per "version:variant", loaded once.
    // These never have keypairFromSeed() called on them, so they are safe to share.
    /** @type {Record<string, MayoSigner>} */
    static #sharedSigners = {};

    // Per-instance signer for sign() — each QsafeSigner has its own MayoSigner.
    // MayoSigner stores secretKey internally after keypairFromSeed(), so sharing
    // across instances would cause one loadMasterKey() to overwrite another's key.
    /** @type {MayoSigner|null} */	#mayoSigner = null;
    /** @type {Uint8Array|null} */	#edPriv = null;
    #version;
    #variant;

    /** @param {string} version  @param {'mayo1' | 'mayo2'} variant */
    constructor(version, variant) { this.#version = version; this.#variant = variant; }

    /** Creates a signer ready for signing with a single version+variant.
     * Ideal for signing use-cases. Each instance gets its own MayoSigner.
     * @param {'mayo1' | 'mayo2'} [variant] - Default: 'mayo1'
     * @param {'1'} [version] - Protocol version. Default: CURRENT_VERSION */
    static async create(variant = DEFAULT_VARIANT, version = CURRENT_VERSION) {
        const proto = PROTOCOL_VERSIONS[version];
        if (!proto) throw new Error(`Unknown protocol version: ${version}`);
        if (!proto.variants[variant]) throw new Error(`Unknown variant '${variant}' for version ${version}`);

        const instance = new QsafeSigner(version, variant);
        await instance.#ensureShared(version, variant);      // for verify()
        instance.#mayoSigner = await proto.loader(variant);  // private instance for sign()
        return instance;
    }

    /** Creates a verifier with all variants of the given versions pre-loaded.
     * Ideal for validators needing backward-compatible verify().
     * Calling loadMasterKey() or sign() on a createFull() instance will throw.
     * @param {string[]} [versions] - Defaults to all known versions. Available: ['1'] */
    static async createFull(versions = AVAILABLE_VERSIONS) {
        const instance = new QsafeSigner(CURRENT_VERSION, DEFAULT_VARIANT);
        for (const version of versions) {
            const proto = PROTOCOL_VERSIONS[version];
            if (!proto) throw new Error(`Unknown protocol version: ${version}`);
            for (const variant in proto.variants)
                await instance.#ensureShared(version, variant); // eslint-disable-line no-await-in-loop
        }
        return instance;
    }

    /** Generates a cryptographically random master seed. @param {16|24|32} [size] - Seed size in bytes. Default: 32 */
    static generateMasterKey(size = 32) {
        if (size !== 16 && size !== 24 && size !== 32) throw new Error('Master key size must be 16, 24 or 32 bytes');
        const seed = new Uint8Array(size);
        crypto.getRandomValues(seed);
        return seed;
    }

	/** Parses a signature header and resolves its protocol version and variant.
	 * - Returns null if the header is invalid or references an unknown version/variant.
	 * @param {Uint8Array} headerOrSignature */
	static parseHeader(headerOrSignature) { return QsafeHelper.parseHeader(headerOrSignature); }

    /** Verifies a hybrid signature. Lazy-loads the required WASM variant if not already cached.
     * - Works with any protocol version whose descriptors are registered above.
	 * - Do not parallelize calls to verify(), async is justified by the lazy WASM loading. To parallelize, please use workers
     * @param {Uint8Array} message
     * @param {Uint8Array} signature  - from sign()
     * @param {Uint8Array} publicKey  - from loadMasterKey() */
    async verify(message, signature, publicKey) {
        const h = QsafeHelper.parseHeader(signature);
		if (!h) return false; // invalid header or unknown version/variant
		if (signature.length !== HEADER_SIZE + ED25519_SIG_SIZE + h.desc.sigSize) return false;
		if (publicKey.length !== ED25519_PUB_SIZE + h.desc.pubKeySize) return false;

        const sigReader = new BinaryReader(signature);
        sigReader.read(HEADER_SIZE); // skip header already parsed
        const edSig   = sigReader.read(ED25519_SIG_SIZE);
        const mayoSig = sigReader.read(h.desc.sigSize);

        const pubReader = new BinaryReader(publicKey);
        const edPub   = pubReader.read(ED25519_PUB_SIZE);
        const mayoPub = pubReader.read(h.desc.pubKeySize);

        // Fast path: ed25519 first (pure JS, no WASM)
        if (!ed25519.verify(edSig, message, edPub)) return false;

        // Lazy-load the shared signer for this version+variant if not already cached
        const signer = await this.#ensureShared(h.version, h.variant);
        return signer.verify(message, mayoSig, mayoPub);
    }

    /** Derives and loads a keypair from a master seed (16–32 bytes).
     * - After this call, sign() is ready to use.
     * - Requires a signer created with create(), not createFull().
     * @param {Uint8Array} masterSeed @returns {Keypair} The generated public + secret key pair */
    loadMasterKey(masterSeed) {
        const isValidSize = (masterSeed instanceof Uint8Array) && (masterSeed.length === 16 || masterSeed.length === 24 || masterSeed.length === 32);
		if (!isValidSize) throw new TypeError('masterSeed must be a Uint8Array of 16, 24 or 32 bytes');
		if (!this.#mayoSigner) throw new Error('No signing instance — use QsafeSigner.create(), not createFull()');

        const proto = PROTOCOL_VERSIONS[this.#version];
        const desc  = proto.variants[this.#variant];
        const { edSeed, mayoSeed } = QsafeHelper.deriveSeeds(masterSeed, desc.seedSize);

        this.#edPriv = edSeed;
        const mayo = this.#mayoSigner.keypairFromSeed(mayoSeed); // stores secretKey in this.#mayoSigner
        if (!mayo || !this.#mayoSigner.ready) throw new Error('MAYO keypair generation failed');

        // publicKey = ed25519_pub(32) + mayo_pub
        const pub = new BinaryWriter(ED25519_PUB_SIZE + desc.pubKeySize);
        pub.writeBytes(ed25519.getPublicKey(edSeed));
        pub.writeBytes(mayo.publicKey);

        // secretKey = variantId(1) + ed25519_priv(32) + mayo_sec(seedSize)
        const sec = new BinaryWriter(1 + ED25519_PRIV_SIZE + desc.seedSize);
        sec.writeByte(VARIANT_ID[this.#variant]);
        sec.writeBytes(edSeed);
        sec.writeBytes(mayo.secretKey);

        return { publicKey: pub.getBytes(), secretKey: sec.getBytes() };
    }

    /** Signs a message. Requires a prior loadMasterKey() call.
     * - The same instance can sign many messages without re-loading the key.
     * @param {Uint8Array} message */
    sign(message) {
        if (!this.#edPriv) throw new Error('No key loaded — call loadMasterKey() first');
        if (!this.#mayoSigner) throw new Error('No signing instance — use QsafeSigner.create(), not createFull()');
        if (!this.#mayoSigner.ready) throw new Error('MAYO signer not ready — was create() called?');

        const proto  = PROTOCOL_VERSIONS[this.#version];
        const desc   = proto.variants[this.#variant];
        const edSig   = ed25519.sign(message, this.#edPriv);
        const mayoSig = this.#mayoSigner.sign(message);
        if (!mayoSig) throw new Error('MAYO sign() returned null');

        // header: version(u16 BE) + variantId(u8)
        const writer = new BinaryWriter(HEADER_SIZE + ED25519_SIG_SIZE + desc.sigSize);
        writer.writeU16BE(Number(this.#version));
        writer.writeByte(VARIANT_ID[this.#variant]);
        writer.writeBytes(edSig);
        writer.writeBytes(mayoSig);

        return writer.getBytes();
    }

    /** Loads and caches a shared MayoSigner for version+variant. Idempotent.
     * These instances are ONLY used for verify() — keypairFromSeed() is never called on them.
     * @param {string} version  @param {'mayo1' | 'mayo2' | string} variant */
    async #ensureShared(version, variant) {
        const key = `${version}:${variant}`;
        if (QsafeSigner.#sharedSigners[key]) return QsafeSigner.#sharedSigners[key];
        const proto  = PROTOCOL_VERSIONS[version];
        const signer = await proto.loader(variant);
        QsafeSigner.#sharedSigners[key] = signer;
        return signer;
    }
}