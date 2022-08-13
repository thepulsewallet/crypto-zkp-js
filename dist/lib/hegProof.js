"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.HEGProof = exports.HomoElGamalStatement = exports.HomoElGamalWitness = void 0;
const BN = require("bn.js");
const crypto_rand_1 = require("@safeheron/crypto-rand");
const cryptoJS = require("crypto-js");
const crypto_utils_1 = require("@safeheron/crypto-utils");
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
class HomoElGamalWitness {
    constructor(r, x) {
        this.r = r;
        this.x = x;
    }
}
exports.HomoElGamalWitness = HomoElGamalWitness;
class HomoElGamalStatement {
    constructor(g, h, y, d, e) {
        this.G = g;
        this.H = h;
        this.Y = y;
        this.D = d;
        this.E = e;
    }
}
exports.HomoElGamalStatement = HomoElGamalStatement;
class HEGProof {
    constructor(t, a3, z1, z2) {
        this.T = t;
        this.A3 = a3;
        this.z1 = z1;
        this.z2 = z2;
    }
    static prove(witness, statement) {
        return __awaiter(this, void 0, void 0, function* () {
            // T = H^s1 + Y^s2
            let s1 = yield crypto_rand_1.Rand.randomBN(32);
            let s2 = yield crypto_rand_1.Rand.randomBN(32);
            let A1 = statement.H.mul(s1);
            let A2 = statement.Y.mul(s2);
            let A3 = statement.G.mul(s2);
            let T = A1.add(A2);
            // e = H(T || A3 || G || H || Y || D || E)
            const sha256 = cryptoJS.algo.SHA256.create();
            sha256.update(crypto_utils_1.Hex.toCryptoJSBytes(T.getX().toString(16)));
            sha256.update(crypto_utils_1.Hex.toCryptoJSBytes(A3.getX().toString(16)));
            sha256.update(crypto_utils_1.Hex.toCryptoJSBytes(statement.G.getX().toString(16)));
            sha256.update(crypto_utils_1.Hex.toCryptoJSBytes(statement.H.getX().toString(16)));
            sha256.update(crypto_utils_1.Hex.toCryptoJSBytes(statement.Y.getX().toString(16)));
            sha256.update(crypto_utils_1.Hex.toCryptoJSBytes(statement.D.getX().toString(16)));
            sha256.update(crypto_utils_1.Hex.toCryptoJSBytes(statement.E.getX().toString(16)));
            const digest = sha256.finalize();
            let e = new BN(cryptoJS.enc.Hex.stringify(digest), 16);
            // z1 = s1 + x * e
            let z1 = s1;
            if (!witness.x.eqn(0)) {
                z1 = s1.add(witness.x.mul(e));
            }
            // z1 = s2 + r * e
            let z2 = s2.add(witness.r.mul(e));
            return new HEGProof(T, A3, z1, z2);
        });
    }
    static proveWithR(witness, statement, s1_lt_curveN, s2_lt_curveN) {
        const s1 = s1_lt_curveN;
        const s2 = s2_lt_curveN;
        // T = H^s1 + Y^s2
        let A1 = statement.H.mul(s1);
        let A2 = statement.Y.mul(s2);
        let A3 = statement.G.mul(s2);
        let T = A1.add(A2);
        // e = H(T || A3 || G || H || Y || D || E)
        const sha256 = cryptoJS.algo.SHA256.create();
        sha256.update(crypto_utils_1.Hex.toCryptoJSBytes(T.getX().toString(16)));
        sha256.update(crypto_utils_1.Hex.toCryptoJSBytes(A3.getX().toString(16)));
        sha256.update(crypto_utils_1.Hex.toCryptoJSBytes(statement.G.getX().toString(16)));
        sha256.update(crypto_utils_1.Hex.toCryptoJSBytes(statement.H.getX().toString(16)));
        sha256.update(crypto_utils_1.Hex.toCryptoJSBytes(statement.Y.getX().toString(16)));
        sha256.update(crypto_utils_1.Hex.toCryptoJSBytes(statement.D.getX().toString(16)));
        sha256.update(crypto_utils_1.Hex.toCryptoJSBytes(statement.E.getX().toString(16)));
        const digest = sha256.finalize();
        let e = new BN(cryptoJS.enc.Hex.stringify(digest), 16);
        // z1 = s1 + x * e
        let z1 = s1;
        if (witness.x != 0) {
            z1 = s1.add(witness.x.mul(e));
        }
        // z2 = s2 + r * e
        let z2 = s2.add(witness.r.mul(e));
        return new HEGProof(T, A3, z1, z2);
    }
    verify(statement) {
        // T = H^s1 + Y^s2
        let T = this.T;
        // A3 = G^s2
        let A3 = this.A3;
        // z1 = s1 + x * e
        let z1 = this.z1;
        // z2 = s2 + r * e
        let z2 = this.z2;
        // e = H(T || A3 || G || H || Y || D || E)
        const sha256 = cryptoJS.algo.SHA256.create();
        sha256.update(crypto_utils_1.Hex.toCryptoJSBytes(T.getX().toString(16)));
        sha256.update(crypto_utils_1.Hex.toCryptoJSBytes(A3.getX().toString(16)));
        sha256.update(crypto_utils_1.Hex.toCryptoJSBytes(statement.G.getX().toString(16)));
        sha256.update(crypto_utils_1.Hex.toCryptoJSBytes(statement.H.getX().toString(16)));
        sha256.update(crypto_utils_1.Hex.toCryptoJSBytes(statement.Y.getX().toString(16)));
        sha256.update(crypto_utils_1.Hex.toCryptoJSBytes(statement.D.getX().toString(16)));
        sha256.update(crypto_utils_1.Hex.toCryptoJSBytes(statement.E.getX().toString(16)));
        const digest = sha256.finalize();
        let e = new BN(cryptoJS.enc.Hex.stringify(digest), 16);
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
exports.HEGProof = HEGProof;
//# sourceMappingURL=hegProof.js.map