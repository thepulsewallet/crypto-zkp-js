import * as BN from "bn.js"
import * as cryptoJS from "crypto-js"
import {Hex} from "@safeheron/crypto-utils"
import {PailPrivKey, PailPubKey} from "@thepulsewallet/crypto-paillier"
import * as assert from "assert";

type TCurve = any
type TCurvePoint = any

const PRIME_UTIL = 6370
const PROOF_ITERS = 11

let BN_ONE = new BN(1)
let BN_ZERO = new BN(0)

function prime_util(n: number): BN[]{
    let primeArr = []
    assert(n > 0)
    if(n < 2) return primeArr;
    for(let i = 3; i <= n; i++){
        let isPrime = true
        for(let p of primeArr){
            if(p * p >= i) {
                break
            }
            if(i % p === 0) {
                isPrime = false
                break
            }
        }
        if(isPrime) primeArr.push(i)
    }
    return primeArr
}

/**
 * Non-interactive Zero-Knowledge Proof of Paillier Public Key
 * Ref：XXX
 */
export class PailProof{
    public readonly yNArr: BN[]

    public constructor(yNArr: BN[]) {
        this.yNArr = yNArr
    }

    private static generateXArr(index: BN, pointX: BN, pointY: BN, N: BN, iters: number): BN[]{
        let xArr = []
        let i = 0;
        let n = 0;
        let SHA256_DIGEST_LENGTH = 32
        let N_Blocks = 1 + N.bitLength() / (SHA256_DIGEST_LENGTH * 8);
        let index_bytes = Hex.toCryptoJSBytes(Hex.padEven(index.toString(16)))
        let pointX_bytes = Hex.toCryptoJSBytes(Hex.padEven(pointX.toString(16)))
        let pointY_bytes = Hex.toCryptoJSBytes(Hex.padEven(pointY.toString(16)))
        let N_bytes = Hex.toCryptoJSBytes(Hex.padEven(N.toString(16)))

        while (i < iters){
            let blocks_buf = cryptoJS.lib.WordArray.create();
            for (let j = 0; j < N_Blocks; j++){
                let i_byte4 = Hex.toCryptoJSBytes(Hex.pad8(i.toString(16)))
                let j_byte4 = Hex.toCryptoJSBytes(Hex.pad8(j.toString(16)))
                let n_byte4 = Hex.toCryptoJSBytes(Hex.pad8(n.toString(16)))
                const sha256 = cryptoJS.algo.SHA256.create()
                sha256.update(i_byte4)
                sha256.update(j_byte4)
                sha256.update(n_byte4)
                sha256.update(index_bytes)
                sha256.update(pointX_bytes)
                sha256.update(pointY_bytes)
                sha256.update(N_bytes)
                const digest = sha256.finalize()
                blocks_buf = blocks_buf.concat(digest)
            }
            let x = new BN(Hex.fromCryptoJSBytes(blocks_buf), 16)
            x = x.umod(N)
            // x in Z_N*
            let ok = x.gt(BN_ONE) && x.lt(N) && (x.gcd(N).eq(BN_ONE))
            if(ok){
                i = i + 1
                xArr.push(x)
            }else {
                n = n + 1
            }
        }
        return xArr
    }

    public static prove(pailPriv: PailPrivKey, index: BN, pointX: BN, pointY: BN): PailProof{
        let yNArr = []
        let M = pailPriv.n.invm(pailPriv.lambda)
        let xArr = PailProof.generateXArr(index, pointX, pointY, pailPriv.n, PROOF_ITERS)
        let red = BN.red(pailPriv.n);
        for(let i = 0; i < xArr.length; i++){
            let x = xArr[i].toRed(red)
            let yN = x.redPow(M)
            yNArr.push(yN.fromRed())
        }
        return new PailProof(yNArr);
    }

    public verify(pailPub: PailPubKey, index: BN, pointX: BN, pointY: BN): boolean{
        if(pailPub.n.bitLength() < 2047) return false;

        // Check pail N
        let primeArr = prime_util(PRIME_UTIL)
        for (let p of primeArr){
            // n % p != 0
            if(pailPub.n.umod(new BN(p)).eq(BN_ZERO)){
                return false
            }
        }

        let xArr = PailProof.generateXArr(index, pointX, pointY, pailPub.n, PROOF_ITERS)
        let red = BN.red(pailPub.n);
        for(let i = 0; i < xArr.length; i++){
            let yRed = this.yNArr[i].toRed(red)
            let x = yRed.redPow(pailPub.n)
            if(!x.eq(xArr[i])) {
                return false
            }
        }
        return true
    }
}
