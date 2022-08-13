import * as BN from "bn.js"
import {SchnorrProof} from "./schnorrProof";
import * as elliptic from "elliptic"
const Secp256k1 = new elliptic.ec('secp256k1')

/**
 * Schnorr Non-interactive Zero-Knowledge Proof
 * Ref：https://tools.ietf.org/html/rfc8235
 */
export class Secp256k1SchnorrProof {
    public readonly pk: any
    public readonly g_r: any
    public readonly res: BN

    public constructor(pk: any ,g_r: any, res: BN) {
        this.pk = pk
        this.g_r = g_r
        this.res = res
    }

    public static async prove(sk: BN): Promise<Secp256k1SchnorrProof> {
        let sp = await SchnorrProof.prove(sk, Secp256k1.g, Secp256k1.n)
        return new Secp256k1SchnorrProof(sp.pk, sp.g_r, sp.res)
    }

    public static proveWithR(sk: BN, r_lt_CurveN: BN): Secp256k1SchnorrProof {
        let sp = SchnorrProof.proveWithR(sk, r_lt_CurveN, Secp256k1.g, Secp256k1.n)
        return new Secp256k1SchnorrProof(sp.pk, sp.g_r, sp.res)
    }

    public verify(): boolean{
        return new SchnorrProof(this.pk, this.g_r, this.res, Secp256k1.g, Secp256k1.n).verify()
    }
}
