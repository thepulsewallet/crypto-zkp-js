import * as BN from "bn.js"
import {SchnorrProof} from "./schnorrProof";
import * as elliptic from "elliptic"
const Ed25519 = new elliptic.eddsa('ed25519');


/**
 * Schnorr Non-interactive Zero-Knowledge Proof
 * Ref：https://tools.ietf.org/html/rfc8235
 */
export class Ed25519SchnorrProof {
    public readonly pk: any
    public readonly g_r: any
    public readonly res: BN

    public constructor(pk: any ,g_r: any, res: BN) {
        this.pk = pk
        this.g_r = g_r
        this.res = res
    }

    public static async prove(sk: BN): Promise<Ed25519SchnorrProof> {
        // @ts-ignore
        let sp = await SchnorrProof.prove(sk, Ed25519.g, Ed25519.curve.n)
        return new Ed25519SchnorrProof(sp.pk, sp.g_r, sp.res)
    }

    public static proveWithR(sk: BN, r_lt_CurveN: BN): Ed25519SchnorrProof {
        // @ts-ignore
        let sp = SchnorrProof.proveWithR(sk, r_lt_CurveN, Ed25519.g, Ed25519.curve.n)
        return new Ed25519SchnorrProof(sp.pk, sp.g_r, sp.res)
    }

    public verify(): boolean{
        // @ts-ignore
        return new SchnorrProof(this.pk, this.g_r, this.res, Ed25519.g, Ed25519.curve.n).verify()
    }
}
