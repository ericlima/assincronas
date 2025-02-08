const crypto = require('crypto');
const fs = require('fs');

// Gera chave privada ECDH
const ecdh = crypto.createECDH('secp521r1');
ecdh.generateKeys();

// Converte a chave privada para o formato PEM
const privateKeyPem = ecdh.getPrivateKey('pem');

// Converte a chave pública para o formato PEM
const publicKeyPem = ecdh.getPublicKey('pem');

// Salva as chaves em arquivos
fs.writeFileSync('private-key.pem', privateKeyPem);
fs.writeFileSync('public-key.pem', publicKeyPem);

console.log('Chaves geradas com sucesso!');