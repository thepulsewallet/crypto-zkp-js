import BN = require('bn.js');
import {Rand} from '@thepulsewallet/crypto-rand'
import {Ed25519SchnorrProof, Secp256k1SchnorrProof, HomoElGamalWitness, HomoElGamalStatement, HEGProof} from ".."
import elliptic = require('elliptic');
import * as assert from "assert";
const Secp256k1 = new elliptic.ec('secp256k1');
const Ed25519 = new elliptic.eddsa('ed25519');


describe('zkp ', function () {
    it('zkp -- hegProof', async function () {
        async function testHegProof(curve) {
            let r = await Rand.randomBN(32);
            let x = await Rand.randomBN(32);
            let witness = new HomoElGamalWitness(r, x);
            const ec = curve
            let G = ec.g;
            let h = await Rand.randomBN(32);
            let H = G.mul(h);
            let y = await Rand.randomBN(32);
            let Y = G.mul(y);
            let D = H.mul(witness.x).add(Y.mul(witness.r));
            let E = G.mul(witness.r);

            let delta = new HomoElGamalStatement(G, H, Y, D, E);

            let proof = await HEGProof.prove(witness, delta)
            assert(proof.verify(delta))

            let s1 = await Rand.randomBN(32)
            let s2 = await Rand.randomBN(32)
            proof = HEGProof.proveWithR(witness, delta, s1, s2)
            assert(proof.verify(delta))
        }

        await testHegProof(Secp256k1)
        await testHegProof(Ed25519)
    })
})
