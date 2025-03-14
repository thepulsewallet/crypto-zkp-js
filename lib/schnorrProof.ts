import * as BN from "bn.js"
import {Rand} from '@thepulsewallet/crypto-rand'
import * as cryptoJS from "crypto-js"
import {Hex} from "@safeheron/crypto-utils";
import * as elliptic from "elliptic"
const Ed25519 = new elliptic.eddsa('ed25519')
const Secp256k1 = new elliptic.ec('secp256k1')

/**
 * Schnorr Non-interactive Zero-Knowledge Proof
 * Ref：https://tools.ietf.org/html/rfc8235
 */
export class SchnorrProof{
    public readonly pk: any
    public readonly g_r: any
    public readonly res: BN
    public readonly g: any
    public readonly n: BN

    public constructor(pk: any ,g_r: any, res: BN, g: any, n: BN) {
        this.pk = pk
        this.g_r = g_r
        this.res = res
        this.g = g
        this.n = n
    }

    public static async prove(sk: BN, g: any, curveN: BN): Promise<SchnorrProof>{
        // r in [0, n-1]
        let r = await Rand.randomBNLt(curveN);
        let g_r = g.mul(r);
        let pk = g.mul(sk);
        // c = H(G || g^r || g^sk || UserID || OtherInfo)
        const sha256 = cryptoJS.algo.SHA256.create()
        sha256.update(Hex.toCryptoJSBytes(g_r.getX().toString(16)))
        sha256.update(Hex.toCryptoJSBytes(g.getX().toString(16)))
        sha256.update(Hex.toCryptoJSBytes(pk.getX().toString(16)))
        const digest = sha256.finalize()
        let c = new BN(cryptoJS.enc.Hex.stringify(digest), 16)
        // res = r - sk * c mod n
        let tres = r.sub(c.mul(sk));
        let res = tres.umod(curveN);
        // proof = [pk, g^r, r - sk * c mod n]
        return new SchnorrProof(pk,g_r,res, g, curveN)
    }

    public static proveWithR(sk: BN, r_lt_CurveN: BN, g: any, curveN: BN): SchnorrProof{
        const r = r_lt_CurveN
        let g_r = g.mul(r);
        let pk = g.mul(sk);
        // c = H(G || g^r || g^sk || UserID || OtherInfo)
        const sha256 = cryptoJS.algo.SHA256.create()
        sha256.update(Hex.toCryptoJSBytes(g_r.getX().toString(16)))
        sha256.update(Hex.toCryptoJSBytes(g.getX().toString(16)))
        sha256.update(Hex.toCryptoJSBytes(pk.getX().toString(16)))
        const digest = sha256.finalize()
        let c = new BN(cryptoJS.enc.Hex.stringify(digest), 16)
        // res = r - sk * c mod n
        let tres = r.sub(c.mul(sk));
        let res = tres.umod(curveN);
        // proof = [pk, g^r, r - sk * c mod n]
        return new SchnorrProof(pk,g_r,res, g, curveN)
    }

    public verify(): boolean{
        // c = H(G || g^r || g^sk || UserID || OtherInfo)
        const sha256 = cryptoJS.algo.SHA256.create()
        sha256.update(Hex.toCryptoJSBytes(this.g_r.getX().toString(16)))
        sha256.update(Hex.toCryptoJSBytes(this.g.getX().toString(16)))
        sha256.update(Hex.toCryptoJSBytes(this.pk.getX().toString(16)))
        const digest = sha256.finalize()
        let c = new BN(cryptoJS.enc.Hex.stringify(digest), 16)
        // Verify: g^r === g^[r - sk * c mod n] + pk * [c]
        let result = this.g.mul(this.res).add(this.pk.mul(c));
        let expected = this.g_r;
        return result.eq(expected);
    }

}
