import BN = require('bn.js');
import {Rand} from '@thepulsewallet/crypto-rand'
import {Ed25519SchnorrProof, Secp256k1SchnorrProof, HomoElGamalWitness, HomoElGamalStatement, HEGProof} from ".."
import elliptic = require('elliptic');
import * as assert from "assert";
const Secp256k1 = new elliptic.ec('secp256k1');
const Ed25519 = new elliptic.eddsa('ed25519');


describe('zkp ', function () {
    it('SchnorrProofSecp256k1', async function () {
        for (let i = 0; i < 10; i++) {
            let sk = await Rand.randomBNLt(Secp256k1.n)
            let proof = await Secp256k1SchnorrProof.prove(sk)
            assert(proof.verify())

            let r = await Rand.randomBN(32)
            proof = Secp256k1SchnorrProof.proveWithR(sk, r)
            assert(proof.verify())
        }
    })

    it('SchnorrProofEd25519', async function () {
        for (let i = 0; i < 10; i++) {
            let sk = await Rand.randomBNLt(Ed25519.curve.n)
            let proof = await Ed25519SchnorrProof.prove(sk)
            assert(proof.verify())

            let r = await Rand.randomBN(32)
            proof = Ed25519SchnorrProof.proveWithR(sk, r)
            assert(proof.verify())
        }
    })
})
