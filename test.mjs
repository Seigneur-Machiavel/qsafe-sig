// @ts-check
import { QsafeHelper, QsafeSigner } from './index.mjs';
import { createRandomMessage, eq } from './test-helpers.mjs';

const NB_OF_TESTS = 100;
const msg1 = createRandomMessage(256); // 256-byte message for quick tests
const msg2 = createRandomMessage(2**17); // 128KB message for testing larger sizes and performance

const SEED_A = crypto.getRandomValues(new Uint8Array(32));
const SEED_B = crypto.getRandomValues(new Uint8Array(32));

/** @param {'mayo1'|'mayo2'} variant */
async function testVariant(variant, log = false) {
	let start = performance.now();

    // -- Keypair determinism --
    const signerA1 = await QsafeSigner.create(variant);
    const signerA2 = await QsafeSigner.create(variant);
    const kpA1 = signerA1.loadMasterKey(SEED_A);
    const kpA2 = signerA2.loadMasterKey(SEED_A);
	if (log) console.log(`- keypair generation time ~${((performance.now() - start) / 2).toFixed(2)} ms`);
    console.assert(eq(kpA1.hybridKey, kpA2.hybridKey), `${variant} hybridKey should be deterministic`);
    console.assert(eq(kpA1.secretKey, kpA2.secretKey), `${variant} secretKey should be deterministic`);
    if (log) console.log(`✓ ${variant} keypair determinism OK`);

    // -- Different seeds → different keypairs --
    const signerB = await QsafeSigner.create(variant);
    const kpB = signerB.loadMasterKey(SEED_B);
    console.assert(!eq(kpA1.hybridKey, kpB.hybridKey), `${variant} collision: same pubKey from different seeds`);
    console.assert(!eq(kpA1.secretKey, kpB.secretKey), `${variant} collision: same secKey from different seeds`);
    if (log) console.log(`✓ ${variant} seed isolation OK`);

    // -- Sign/verify roundtrip --
	start = performance.now();
    const sig1 = signerA1.sign(msg1);
    const sig2 = signerA1.sign(msg2);
	if (log) console.log(`✓ ${variant} signing OK ~${((performance.now() - start) / 2).toFixed(2)} ms`);
	
	start = performance.now();
    const verifier = await QsafeSigner.createFull();
    console.assert( await verifier.verify(msg1, sig1, kpA1.hybridKey),  `${variant} sig1/msg1 rejected`);
    console.assert( await verifier.verify(msg2, sig2, kpA1.hybridKey),  `${variant} sig2/msg2 rejected`);

	console.assert(!await verifier.verify(msg2, sig1, kpA1.hybridKey),  `${variant} sig1 wrongly accepts msg2`);
    console.assert(!await verifier.verify(msg1, sig2, kpA1.hybridKey),  `${variant} sig2 wrongly accepts msg1`);
    if (log) console.log(`✓ ${variant} verifying OK ~${((performance.now() - start) / 4).toFixed(2)} ms`);

    // -- Wrong public key → rejected --
    console.assert(!await verifier.verify(msg1, sig1, kpB.hybridKey), `${variant} wrong pubkey wrongly accepted`);
    if (log) console.log(`✓ ${variant} cross-key rejection OK`);

	// -- Tampered signature → rejected by verify() --
	const sigTampered = sig1.slice();
	const tamperedIdx = 3 + Math.floor(Math.random() * (sig1.length - 3)); // random byte past the 3-byte header
	sigTampered[tamperedIdx] ^= 0xFF;
	console.assert(!await verifier.verify(msg1, sigTampered, kpA1.hybridKey), `${variant} tampered sig wrongly accepted (flipped byte at index ${tamperedIdx})`);
	if (log) console.log(`✓ ${variant} tampered sig rejection OK (flipped byte at index ${tamperedIdx})`);

	// -- Tampered message → rejected --
	const msgTampered = msg1.slice();
	const msgTamperedIdx = Math.floor(Math.random() * msg1.length);
	msgTampered[msgTamperedIdx] ^= 0xFF;
	console.assert(!await verifier.verify(msgTampered, sig1, kpA1.hybridKey), `${variant} tampered msg wrongly accepted (flipped byte at index ${msgTamperedIdx})`);
	if (log) console.log(`✓ ${variant} tampered msg rejection OK (flipped byte at index ${msgTamperedIdx})`);
}

console.log(`-- Testing mayo1 --`);
for (let i = 0; i < NB_OF_TESTS - 1; i++) await testVariant('mayo1');
await testVariant('mayo1', true); // last test: full logs.

console.log(`-- Testing mayo2 --`);
for (let i = 0; i < NB_OF_TESTS - 1; i++) await testVariant('mayo2');
await testVariant('mayo2', true); // last test: full logs.

console.log('-- TEST END --');