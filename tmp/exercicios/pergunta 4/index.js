const crypto = require('crypto');

const curveType='secp521r1'; //'secp256k1';

console.log(`\r\nUsing the ${curveType} curve`)

// Generate a keypair for Alice
const alice = crypto.createECDH(curveType);
alice.generateKeys();

// Generate a keypair for Bob
const bob = crypto.createECDH(curveType);
bob.generateKeys();

// print alice's keys in hex
console.log("\nAlice private key:\t",alice.getPrivateKey().toString('hex'));
console.log("Alice public key:\t",alice.getPublicKey().toString('hex'))

// print bob's keys in hex
console.log("\nBob private key:\t",bob.getPrivateKey().toString('hex'));
console.log("Bob public key:\t",bob.getPublicKey().toString('hex'));

// generate the shared secret key
// alice uses its private key and bob's public key
const aliceSecret = alice.computeSecret(bob.getPublicKey());
// whereas bob uses its private key and alices's public key
const bobSecret = bob.computeSecret(alice.getPublicKey());

// both the computed keys should be exactly equal
console.log("\nAlice shared key:\t",aliceSecret.toString('hex'))
console.log("Bob shared key:\t\t",bobSecret.toString('hex'));
