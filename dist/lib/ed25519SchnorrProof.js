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
exports.Ed25519SchnorrProof = void 0;
const schnorrProof_1 = require("./schnorrProof");
const elliptic = require("elliptic");
const Ed25519 = new elliptic.eddsa('ed25519');
/**
 * Schnorr Non-interactive Zero-Knowledge Proof
 * Ref：https://tools.ietf.org/html/rfc8235
 */
class Ed25519SchnorrProof {
    constructor(pk, g_r, res) {
        this.pk = pk;
        this.g_r = g_r;
        this.res = res;
    }
    static prove(sk) {
        return __awaiter(this, void 0, void 0, function* () {
            let sp = yield schnorrProof_1.SchnorrProof.prove(sk, Ed25519.g, Ed25519.curve.n);
            return new Ed25519SchnorrProof(sp.pk, sp.g_r, sp.res);
        });
    }
    static proveWithR(sk, r_lt_CurveN) {
        let sp = schnorrProof_1.SchnorrProof.proveWithR(sk, r_lt_CurveN, Ed25519.g, Ed25519.curve.n);
        return new Ed25519SchnorrProof(sp.pk, sp.g_r, sp.res);
    }
    verify() {
        return new schnorrProof_1.SchnorrProof(this.pk, this.g_r, this.res, Ed25519.g, Ed25519.curve.n).verify();
    }
}
exports.Ed25519SchnorrProof = Ed25519SchnorrProof;
//# sourceMappingURL=ed25519SchnorrProof.js.map