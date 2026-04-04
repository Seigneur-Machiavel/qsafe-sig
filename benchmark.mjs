// @ts-check
import { QsafeSigner } from './index.mjs';
import { createRandomMessage } from './test-helpers.mjs';

const SEED = crypto.getRandomValues(new Uint8Array(32));
const COUNT = 1000;
const MSG_SIZE = 256;

/** @param {'mayo1'|'mayo2'} variant */
async function chainVerify(variant) {
    console.log(`\n-- Chain verify x${COUNT}: ${variant} --`);

    const signer = await QsafeSigner.create(variant);
    const { publicKey } = signer.loadMasterKey(SEED);

    // -- Sign phase --
    const messages = [];
    const sigs = [];
    for (let i = 0; i < COUNT; i++) messages.push(createRandomMessage(MSG_SIZE));
	
    const t0sign = performance.now();
	for (const msg of messages) sigs.push(signer.sign(msg));
	
    const signMs = performance.now() - t0sign;
    console.log(`Sign   : ${signMs.toFixed(2)} ms total | ~${(signMs / COUNT).toFixed(3)} ms/op`);

    // -- Verify phase --
    const verifier = await QsafeSigner.createFull();
    let failures = 0;

    const t0verify = performance.now();
    for (let i = 0; i < COUNT; i++)
        if (!await verifier.verify(messages[i], sigs[i], publicKey)) failures++;
	
    const verifyMs = performance.now() - t0verify;
    console.log(`Verify : ${verifyMs.toFixed(2)} ms total | ~${(verifyMs / COUNT).toFixed(3)} ms/op`);

    if (failures > 0) console.error(`✗ ${failures} verification(s) failed!`);
    else console.log(`✓ All ${COUNT} signatures verified successfully`);
}

await chainVerify('mayo1');
await chainVerify('mayo2');

console.log('\n-- DONE --');