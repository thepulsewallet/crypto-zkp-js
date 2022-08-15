import BN = require('bn.js');
import {Rand} from '@safeheron/crypto-rand'
import {PailProof} from ".."
import {createPailKeyPair} from "@safeheron/crypto-paillier";
import * as assert from "assert";
import elliptic = require('elliptic');
const Secp256k1 = new elliptic.ec('secp256k1');


describe('zkp ', function () {
    it('Pail N', async function () {
        console.time("createPailKeyPair --- 2048")
        const [pailPriv, pailPub] = await createPailKeyPair(2048/8)
        console.timeEnd("createPailKeyPair --- 2048")
        let index = await Rand.randomBN(32)
        let r = await Rand.randomBN(32)
        let point = Secp256k1.g.mul(r)
        console.time("PailProof.prove")
        let proof = PailProof.prove(pailPriv, index, point.getX(), point.getY())
        console.timeEnd("PailProof.prove")
        console.time("PailProof.verify")
        console.assert(proof.verify(pailPub, index, point.getX(), point.getY()))
        console.timeEnd("PailProof.verify")
    })
})
