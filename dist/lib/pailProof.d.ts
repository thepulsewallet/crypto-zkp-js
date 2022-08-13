import * as BN from "bn.js";
import { PailPrivKey, PailPubKey } from "@safeheron/crypto-paillier";
/**
 * Non-interactive Zero-Knowledge Proof of Paillier Public Key
 * Ref：XXX
 */
export declare class PailProof {
    readonly yNArr: BN[];
    constructor(yNArr: BN[]);
    private static generateXArr;
    static prove(pailPriv: PailPrivKey, index: BN, pointX: BN, pointY: BN): PailProof;
    verify(pailPub: PailPubKey, index: BN, pointX: BN, pointY: BN): boolean;
}
