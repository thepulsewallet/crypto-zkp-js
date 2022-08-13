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
exports.Secp256k1SchnorrProof = void 0;
const schnorrProof_1 = require("./schnorrProof");
const elliptic = require("elliptic");
const Secp256k1 = new elliptic.ec('secp256k1');
/**
 * Schnorr Non-interactive Zero-Knowledge Proof
 * Ref：https://tools.ietf.org/html/rfc8235
 */
class Secp256k1SchnorrProof {
    constructor(pk, g_r, res) {
        this.pk = pk;
        this.g_r = g_r;
        this.res = res;
    }
    static prove(sk) {
        return __awaiter(this, void 0, void 0, function* () {
            let sp = yield schnorrProof_1.SchnorrProof.prove(sk, Secp256k1.g, Secp256k1.n);
            return new Secp256k1SchnorrProof(sp.pk, sp.g_r, sp.res);
        });
    }
    static proveWithR(sk, r_lt_CurveN) {
        let sp = schnorrProof_1.SchnorrProof.proveWithR(sk, r_lt_CurveN, Secp256k1.g, Secp256k1.n);
        return new Secp256k1SchnorrProof(sp.pk, sp.g_r, sp.res);
    }
    verify() {
        return new schnorrProof_1.SchnorrProof(this.pk, this.g_r, this.res, Secp256k1.g, Secp256k1.n).verify();
    }
}
exports.Secp256k1SchnorrProof = Secp256k1SchnorrProof;
//# sourceMappingURL=secp256k1SchnorrProof.js.map