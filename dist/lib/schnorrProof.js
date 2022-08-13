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
exports.SchnorrProof = void 0;
const BN = require("bn.js");
const crypto_rand_1 = require("@safeheron/crypto-rand");
const cryptoJS = require("crypto-js");
const crypto_utils_1 = require("@safeheron/crypto-utils");
const elliptic = require("elliptic");
const Ed25519 = new elliptic.eddsa('ed25519');
const Secp256k1 = new elliptic.ec('secp256k1');
/**
 * Schnorr Non-interactive Zero-Knowledge Proof
 * Ref：https://tools.ietf.org/html/rfc8235
 */
class SchnorrProof {
    constructor(pk, g_r, res, g, n) {
        this.pk = pk;
        this.g_r = g_r;
        this.res = res;
        this.g = g;
        this.n = n;
    }
    static prove(sk, g, curveN) {
        return __awaiter(this, void 0, void 0, function* () {
            // r in [0, n-1]
            let r = yield crypto_rand_1.Rand.randomBNLt(curveN);
            let g_r = g.mul(r);
            let pk = g.mul(sk);
            // c = H(G || g^r || g^sk || UserID || OtherInfo)
            const sha256 = cryptoJS.algo.SHA256.create();
            sha256.update(crypto_utils_1.Hex.toCryptoJSBytes(g_r.getX().toString(16)));
            sha256.update(crypto_utils_1.Hex.toCryptoJSBytes(g.getX().toString(16)));
            sha256.update(crypto_utils_1.Hex.toCryptoJSBytes(pk.getX().toString(16)));
            const digest = sha256.finalize();
            let c = new BN(cryptoJS.enc.Hex.stringify(digest), 16);
            // res = r - sk * c mod n
            let tres = r.sub(c.mul(sk));
            let res = tres.umod(curveN);
            // proof = [pk, g^r, r - sk * c mod n]
            return new SchnorrProof(pk, g_r, res, g, curveN);
        });
    }
    static proveWithR(sk, r_lt_CurveN, g, curveN) {
        const r = r_lt_CurveN;
        let g_r = g.mul(r);
        let pk = g.mul(sk);
        // c = H(G || g^r || g^sk || UserID || OtherInfo)
        const sha256 = cryptoJS.algo.SHA256.create();
        sha256.update(crypto_utils_1.Hex.toCryptoJSBytes(g_r.getX().toString(16)));
        sha256.update(crypto_utils_1.Hex.toCryptoJSBytes(g.getX().toString(16)));
        sha256.update(crypto_utils_1.Hex.toCryptoJSBytes(pk.getX().toString(16)));
        const digest = sha256.finalize();
        let c = new BN(cryptoJS.enc.Hex.stringify(digest), 16);
        // res = r - sk * c mod n
        let tres = r.sub(c.mul(sk));
        let res = tres.umod(curveN);
        // proof = [pk, g^r, r - sk * c mod n]
        return new SchnorrProof(pk, g_r, res, g, curveN);
    }
    verify() {
        // c = H(G || g^r || g^sk || UserID || OtherInfo)
        const sha256 = cryptoJS.algo.SHA256.create();
        sha256.update(crypto_utils_1.Hex.toCryptoJSBytes(this.g_r.getX().toString(16)));
        sha256.update(crypto_utils_1.Hex.toCryptoJSBytes(this.g.getX().toString(16)));
        sha256.update(crypto_utils_1.Hex.toCryptoJSBytes(this.pk.getX().toString(16)));
        const digest = sha256.finalize();
        let c = new BN(cryptoJS.enc.Hex.stringify(digest), 16);
        // Verify: g^r === g^[r - sk * c mod n] + pk * [c]
        let result = this.g.mul(this.res).add(this.pk.mul(c));
        let expected = this.g_r;
        return result.eq(expected);
    }
}
exports.SchnorrProof = SchnorrProof;
//# sourceMappingURL=schnorrProof.js.map