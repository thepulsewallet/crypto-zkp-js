import * as BN from "bn.js";
/**
 * Schnorr Non-interactive Zero-Knowledge Proof
 * Ref：https://tools.ietf.org/html/rfc8235
 */
export declare class Ed25519SchnorrProof {
    readonly pk: any;
    readonly g_r: any;
    readonly res: BN;
    constructor(pk: any, g_r: any, res: BN);
    static prove(sk: BN): Promise<Ed25519SchnorrProof>;
    static proveWithR(sk: BN, r_lt_CurveN: BN): Ed25519SchnorrProof;
    verify(): boolean;
}
