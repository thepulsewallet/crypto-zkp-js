# crypto-zkp-js
# Installation
```shell
npm install @safeheron/crypto-zkp
```

Import the library in code:
```javascript
import {Ed25519SchnorrProof, Secp256k1SchnorrProof, HomoElGamalWitness, HomoElGamalStatement, HEGProof} from "@safeheron/crypto-zkp"
```

# Examples

## Schnorr proof on curve Secp2561

- Without external random number.
```javascript
let sk = await Rand.randomBNLt(Secp256k1.n)
let proof = await Secp256k1SchnorrProof.prove(sk)
assert(proof.verify())
```


- With external random number.
```javascript
let sk = await Rand.randomBNLt(Secp256k1.n)
let r = await Rand.randomBN(32)
let proof = Secp256k1SchnorrProof.proveWithR(sk, r)
assert(proof.verify())
```

## Schnorr proof on curve Secp2561

- Without external random number.
```javascript
let sk = await Rand.randomBNLt(Ed25519.curve.n)
let proof = await Ed25519SchnorrProof.prove(sk)
assert(proof.verify())
```


- With external random number.
```javascript
let sk = await Rand.randomBNLt(Ed25519.curve.n)
let r = await Rand.randomBN(32)
let proof = Ed25519SchnorrProof.proveWithR(sk, r)
assert(proof.verify())
```

## Proof of Homo ElGamal

```javascript
let r = await Rand.randomBN(32);
let x = await Rand.randomBN(32);
let witness = new HomoElGamalWitness(r,x);
let G = Ed25519.g;
let h = await Rand.randomBN(32);
let H = G.mul(h);
let y = await Rand.randomBN(32);
let Y = G.mul(y);
let D = H.mul(witness.x).add(Y.mul(witness.r));
let E = G.mul(witness.r);

let delta = new HomoElGamalStatement(G,H,Y,D,E);

let proof = await HEGProof.prove(witness, delta)
assert(proof.verify(delta))
```
