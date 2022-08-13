import * as BN from "bn.js";
/** This is a proof of knowledge that a pair of group elements {D, E}
 * form a valid homomorphic ElGamal encryption (”in the exponent”) using public key Y .
 * (HEG is defined in B. Schoenmakers and P. Tuyls. Practical Two-Party Computation Based on the Conditional Gate)
 * Specifically, the witness is ω = (x, r), the statement is δ = (G, H, Y, D, E).
 * The relation R outputs 1 if D = xH+rY , E = rG (for the case of G=H this is ElGamal)
 *
 *
 * Statement: δ = (G, H, Y, D, E).
 * Witness:   ω = (x, r)
 * Prove relation: D = xH + rY and E=rG
 */
export declare class HomoElGamalWitness {
    readonly r: BN;
    readonly x: BN;
    constructor(r: BN, x: BN);
}
export declare class HomoElGamalStatement {
    readonly G: any;
    readonly H: any;
    readonly Y: any;
    readonly D: any;
    readonly E: any;
    constructor(g: any, h: any, y: any, d: any, e: any);
}
export declare class HEGProof {
    readonly T: any;
    readonly A3: any;
    readonly z1: BN;
    readonly z2: BN;
    constructor(t: any, a3: any, z1: BN, z2: BN);
    static prove(witness: HomoElGamalWitness, statement: HomoElGamalStatement): Promise<HEGProof>;
    static proveWithR(witness: HomoElGamalWitness, statement: HomoElGamalStatement, s1_lt_curveN: BN, s2_lt_curveN: BN): HEGProof;
    verify(statement: HomoElGamalStatement): boolean;
}
