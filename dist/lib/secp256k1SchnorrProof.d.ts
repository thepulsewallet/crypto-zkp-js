import * as BN from "bn.js";
/**
 * Schnorr Non-interactive Zero-Knowledge Proof
 * Ref：https://tools.ietf.org/html/rfc8235
 */
export declare class Secp256k1SchnorrProof {
    readonly pk: any;
    readonly g_r: any;
    readonly res: BN;
    constructor(pk: any, g_r: any, res: BN);
    static prove(sk: BN): Promise<Secp256k1SchnorrProof>;
    static proveWithR(sk: BN, r_lt_CurveN: BN): Secp256k1SchnorrProof;
    verify(): boolean;
}
