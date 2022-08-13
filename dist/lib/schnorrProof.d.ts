import * as BN from "bn.js";
/**
 * Schnorr Non-interactive Zero-Knowledge Proof
 * Ref：https://tools.ietf.org/html/rfc8235
 */
export declare class SchnorrProof {
    readonly pk: any;
    readonly g_r: any;
    readonly res: BN;
    readonly g: any;
    readonly n: BN;
    constructor(pk: any, g_r: any, res: BN, g: any, n: BN);
    static prove(sk: BN, g: any, curveN: BN): Promise<SchnorrProof>;
    static proveWithR(sk: BN, r_lt_CurveN: BN, g: any, curveN: BN): SchnorrProof;
    verify(): boolean;
}
