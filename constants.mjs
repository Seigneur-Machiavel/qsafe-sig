// @ts-check
import { MayoSigner } from '@pinkparrot/qsafe-mayo-wasm';

/**
 * @typedef {{ sigSize: number, pubKeySize: number, seedSize: number }} VariantDesc
 * @typedef {{ publicKey: Uint8Array, secretKey: Uint8Array }} Keypair */

/** Versioned protocol descriptors and loaders.
 * - Each version entry describes the crypto params for that protocol version.
 * - When MAYO bumps its params, add a new version entry pointing to the new package.
 * - Never remove old entries — they are needed for backward-compatible verify().
 * @type {Record<string, { variants: Record<string, VariantDesc>, loader: (variant: string) => Promise<MayoSigner> }>} */
const PROTOCOL_VERSIONS = {
    '1': {
        variants: {
            /** @type {VariantDesc} */
            'mayo1': { sigSize: 454,  pubKeySize: 1420, seedSize: 24 },
            /** @type {VariantDesc} */
            'mayo2': { sigSize: 186,  pubKeySize: 4912, seedSize: 24 },
        },
        // If a future version needs a different wasm package, add a loader here.
        // For v1 both variants come from the same @pinkparrot/qsafe-mayo-wasm import.
        loader: /** @param {string} variant */ async (variant) => await MayoSigner.create(variant),
    },
};

const CURRENT_VERSION  = '1';      // Current protocol version used when signing.
const DEFAULT_VARIANT  = 'mayo1';  // Default variant used when signing.
const AVAILABLE_VERSIONS = Object.keys(PROTOCOL_VERSIONS);

const HKDF_INFO_ED25519 = new TextEncoder().encode('qsafe-ed25519');
const HKDF_INFO_MAYO    = new TextEncoder().encode('qsafe-mayo');

const ED25519_PRIV_SIZE = 32;
const ED25519_PUB_SIZE  = 32;
const ED25519_SIG_SIZE  = 64;

const HEADER_SIZE = 3; // Header layout: version(u16 BE) + variant_id(u8) = 3 bytes
const VARIANT_ID    = { 'mayo1': 0x01, 'mayo2': 0x02 }; // variant_id byte values — stable across protocol versions
/** @type {Record<number, 'mayo1' | 'mayo2'>} */
const VARIANT_BY_ID = { 0x01: 'mayo1', 0x02: 'mayo2' }; // Reverse lookup for parsing signature headers

export {
	PROTOCOL_VERSIONS,
	CURRENT_VERSION,
	DEFAULT_VARIANT,
	AVAILABLE_VERSIONS,
	HKDF_INFO_ED25519,
	HKDF_INFO_MAYO,
	ED25519_PRIV_SIZE,
	ED25519_PUB_SIZE,
	ED25519_SIG_SIZE,
	HEADER_SIZE,
	VARIANT_ID,
	VARIANT_BY_ID
}