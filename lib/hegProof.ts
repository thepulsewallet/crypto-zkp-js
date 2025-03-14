import * as BN from "bn.js"
import {Rand} from '@thepulsewallet/crypto-rand'
import * as cryptoJS from "crypto-js"
import {Hex} from "@safeheron/crypto-utils";

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

export class HomoElGamalWitness{
    public readonly r: BN
    public readonly x: BN

    constructor(r: BN, x: BN) {
        this.r = r;
        this.x = x;
    }
}

export class HomoElGamalStatement{
    public readonly G: any
    public readonly H: any
    public readonly Y: any
    public readonly D: any
    public readonly E: any

    constructor(g: any, h: any, y: any, d: any, e: any) {
        this.G = g;
        this.H = h;
        this.Y = y;
        this.D = d;
        this.E = e;
    }
}

export class HEGProof{
    public readonly T: any;
    public readonly A3: any;
    public readonly z1: BN;
    public readonly z2: BN;

    constructor(t: any, a3: any, z1: BN, z2: BN) {
        this.T = t;
        this.A3 = a3;
        this.z1 = z1;
        this.z2 = z2;
    }

   public static async prove (witness: HomoElGamalWitness, statement: HomoElGamalStatement): Promise<HEGProof>{
        // T = H^s1 + Y^s2
        let s1 = await Rand.randomBN(32);
        let s2 = await Rand.randomBN(32);
        let A1 = statement.H.mul(s1);
        let A2 = statement.Y.mul(s2);
        let A3 = statement.G.mul(s2);
        let T = A1.add(A2)

        // e = H(T || A3 || G || H || Y || D || E)
        const sha256 = cryptoJS.algo.SHA256.create()
        sha256.update(Hex.toCryptoJSBytes(T.getX().toString(16)))
        sha256.update(Hex.toCryptoJSBytes(A3.getX().toString(16)))
        sha256.update(Hex.toCryptoJSBytes(statement.G.getX().toString(16)))
        sha256.update(Hex.toCryptoJSBytes(statement.H.getX().toString(16)))
        sha256.update(Hex.toCryptoJSBytes(statement.Y.getX().toString(16)))
        sha256.update(Hex.toCryptoJSBytes(statement.D.getX().toString(16)))
        sha256.update(Hex.toCryptoJSBytes(statement.E.getX().toString(16)))
        const digest = sha256.finalize()
        let e = new BN(cryptoJS.enc.Hex.stringify(digest), 16)
        // z1 = s1 + x * e
        let z1 = s1;
        if (!witness.x.eqn(0)){
            z1 = s1.add(witness.x.mul(e));
        }
        // z1 = s2 + r * e
        let z2 = s2.add(witness.r.mul(e));
        return new HEGProof(T,A3,z1,z2);
    }

    public static proveWithR(witness: HomoElGamalWitness, statement: HomoElGamalStatement, s1_lt_curveN: BN, s2_lt_curveN: BN): HEGProof{
        const s1 = s1_lt_curveN
        const s2 = s2_lt_curveN
        // T = H^s1 + Y^s2
        let A1 = statement.H.mul(s1);
        let A2 = statement.Y.mul(s2);
        let A3 = statement.G.mul(s2);
        let T = A1.add(A2)

        // e = H(T || A3 || G || H || Y || D || E)
        const sha256 = cryptoJS.algo.SHA256.create()
        sha256.update(Hex.toCryptoJSBytes(T.getX().toString(16)))
        sha256.update(Hex.toCryptoJSBytes(A3.getX().toString(16)))
        sha256.update(Hex.toCryptoJSBytes(statement.G.getX().toString(16)))
        sha256.update(Hex.toCryptoJSBytes(statement.H.getX().toString(16)))
        sha256.update(Hex.toCryptoJSBytes(statement.Y.getX().toString(16)))
        sha256.update(Hex.toCryptoJSBytes(statement.D.getX().toString(16)))
        sha256.update(Hex.toCryptoJSBytes(statement.E.getX().toString(16)))
        const digest = sha256.finalize()
        let e = new BN(cryptoJS.enc.Hex.stringify(digest), 16)

        // z1 = s1 + x * e
        let z1 = s1;
        // @ts-ignore
        if (witness.x != 0){
            z1 = s1.add(witness.x.mul(e));
        }
        // z2 = s2 + r * e
        let z2 = s2.add(witness.r.mul(e));
        return new HEGProof(T,A3,z1,z2);
    }

    public verify(statement: HomoElGamalStatement): boolean{
        // T = H^s1 + Y^s2
        let T = this.T;
        // A3 = G^s2
        let A3 = this.A3;
        // z1 = s1 + x * e
        let z1 = this.z1;
        // z2 = s2 + r * e
        let z2 = this.z2;

        // e = H(T || A3 || G || H || Y || D || E)
        const sha256 = cryptoJS.algo.SHA256.create()
        sha256.update(Hex.toCryptoJSBytes(T.getX().toString(16)))
        sha256.update(Hex.toCryptoJSBytes(A3.getX().toString(16)))
        sha256.update(Hex.toCryptoJSBytes(statement.G.getX().toString(16)))
        sha256.update(Hex.toCryptoJSBytes(statement.H.getX().toString(16)))
        sha256.update(Hex.toCryptoJSBytes(statement.Y.getX().toString(16)))
        sha256.update(Hex.toCryptoJSBytes(statement.D.getX().toString(16)))
        sha256.update(Hex.toCryptoJSBytes(statement.E.getX().toString(16)))
        const digest = sha256.finalize()
        let e = new BN(cryptoJS.enc.Hex.stringify(digest), 16)

        // H^z1 + Y^z2
        let z1H_plus_z2Y = statement.H.mul(z1).add(statement.Y.mul(z2));
        // H^s1 + Y^s2 + D^e
        let T_plus_eD = T.add(statement.D.mul(e));
        // G^z2
        let z2G = statement.G.mul(z2);
        // A3 + E^e
        let A3_plus_eE = A3.add(statement.E.mul(e));
        return (z1H_plus_z2Y.eq(T_plus_eD) && z2G.eq(A3_plus_eE));
    }
}

