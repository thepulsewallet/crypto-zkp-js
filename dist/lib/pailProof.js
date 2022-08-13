"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PailProof = void 0;
const BN = require("bn.js");
const cryptoJS = require("crypto-js");
const crypto_utils_1 = require("@safeheron/crypto-utils");
const assert = require("assert");
const PRIME_UTIL = 6370;
const PROOF_ITERS = 11;
let BN_ONE = new BN(1);
let BN_ZERO = new BN(0);
function prime_util(n) {
    let primeArr = [];
    assert(n > 0);
    if (n < 2)
        return primeArr;
    for (let i = 3; i <= n; i++) {
        let isPrime = true;
        for (let p of primeArr) {
            if (p * p >= i) {
                break;
            }
            if (i % p === 0) {
                isPrime = false;
                break;
            }
        }
        if (isPrime)
            primeArr.push(i);
    }
    return primeArr;
}
/**
 * Non-interactive Zero-Knowledge Proof of Paillier Public Key
 * Ref：XXX
 */
class PailProof {
    constructor(yNArr) {
        this.yNArr = yNArr;
    }
    static generateXArr(index, pointX, pointY, N, iters) {
        let xArr = [];
        let i = 0;
        let n = 0;
        let SHA256_DIGEST_LENGTH = 32;
        let N_Blocks = 1 + N.bitLength() / (SHA256_DIGEST_LENGTH * 8);
        let index_bytes = crypto_utils_1.Hex.toCryptoJSBytes(crypto_utils_1.Hex.padEven(index.toString(16)));
        let pointX_bytes = crypto_utils_1.Hex.toCryptoJSBytes(crypto_utils_1.Hex.padEven(pointX.toString(16)));
        let pointY_bytes = crypto_utils_1.Hex.toCryptoJSBytes(crypto_utils_1.Hex.padEven(pointY.toString(16)));
        let N_bytes = crypto_utils_1.Hex.toCryptoJSBytes(crypto_utils_1.Hex.padEven(N.toString(16)));
        while (i < iters) {
            let blocks_buf = cryptoJS.lib.WordArray.create();
            for (let j = 0; j < N_Blocks; j++) {
                let i_byte4 = crypto_utils_1.Hex.toCryptoJSBytes(crypto_utils_1.Hex.pad8(i.toString(16)));
                let j_byte4 = crypto_utils_1.Hex.toCryptoJSBytes(crypto_utils_1.Hex.pad8(j.toString(16)));
                let n_byte4 = crypto_utils_1.Hex.toCryptoJSBytes(crypto_utils_1.Hex.pad8(n.toString(16)));
                const sha256 = cryptoJS.algo.SHA256.create();
                sha256.update(i_byte4);
                sha256.update(j_byte4);
                sha256.update(n_byte4);
                sha256.update(index_bytes);
                sha256.update(pointX_bytes);
                sha256.update(pointY_bytes);
                sha256.update(N_bytes);
                const digest = sha256.finalize();
                blocks_buf = blocks_buf.concat(digest);
            }
            let x = new BN(crypto_utils_1.Hex.fromCryptoJSBytes(blocks_buf), 16);
            x = x.umod(N);
            // x in Z_N*
            let ok = x.gt(BN_ONE) && x.lt(N) && (x.gcd(N).eq(BN_ONE));
            if (ok) {
                i = i + 1;
                xArr.push(x);
            }
            else {
                n = n + 1;
            }
        }
        return xArr;
    }
    static prove(pailPriv, index, pointX, pointY) {
        let yNArr = [];
        let M = pailPriv.n.invm(pailPriv.lambda);
        let xArr = PailProof.generateXArr(index, pointX, pointY, pailPriv.n, PROOF_ITERS);
        let red = BN.red(pailPriv.n);
        for (let i = 0; i < xArr.length; i++) {
            let x = xArr[i].toRed(red);
            let yN = x.redPow(M);
            yNArr.push(yN.fromRed());
        }
        return new PailProof(yNArr);
    }
    verify(pailPub, index, pointX, pointY) {
        if (pailPub.n.bitLength() < 2047)
            return false;
        // Check pail N
        let primeArr = prime_util(PRIME_UTIL);
        for (let p of primeArr) {
            // n % p != 0
            if (pailPub.n.umod(new BN(p)).eq(BN_ZERO)) {
                return false;
            }
        }
        let xArr = PailProof.generateXArr(index, pointX, pointY, pailPub.n, PROOF_ITERS);
        let red = BN.red(pailPub.n);
        for (let i = 0; i < xArr.length; i++) {
            let yRed = this.yNArr[i].toRed(red);
            let x = yRed.redPow(pailPub.n);
            if (!x.eq(xArr[i])) {
                return false;
            }
        }
        return true;
    }
}
exports.PailProof = PailProof;
//# sourceMappingURL=pailProof.js.map