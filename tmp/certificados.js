const crypto = require('crypto');
const assert = require('assert');

// Generate cliente's keys...
const cliente = crypto.createECDH('secp521r1');
const clienteKey = cliente.generateKeys();

// Generate servidor's keys...
const servidor = crypto.createECDH('secp521r1');
const servidorKey = servidor.generateKeys();

console.log("\ncliente private key:\t",cliente.getPrivateKey().toString('hex'));
console.log("cliente public key:\t",clienteKey.toString('hex'))
console.log("\nservidor private key:\t",servidor.getPrivateKey().toString('hex'));
console.log("servidor public key:\t",servidorKey.toString('hex'));

// Exchange and generate the secret...
const clienteSecret = cliente.computeSecret(servidorKey);
const servidorSecret = servidor.computeSecret(clienteKey);

//assert.strictEqual(clienteSecret.toString('hex'), servidorSecret.toString('hex'));

console.log(clienteSecret.toString('hex'));
console.log(servidorSecret.toString('hex'));

// OK