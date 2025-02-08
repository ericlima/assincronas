const express = require('express');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const port = 6000;

// Middleware para permitir JSON no corpo da requisição
app.use(express.json({ limit: '50mb' }));

// Caminhos das chaves
//const PRIVATE_KEY_PATH = './private-key.pem';
const SENDER_PUBLIC_KEY_PATH = '../public-key.base64'; // Chave pública do cliente

// Carrega a chave privada do servidor
//const privateKey = fs.readFileSync(PRIVATE_KEY_PATH, 'utf8');

// Carrega a chave pública do cliente (para verificar assinatura)
const senderPublicKey = fs.readFileSync(SENDER_PUBLIC_KEY_PATH, 'utf8').trim();

// Gera um par de chaves ECDH para calcular o segredo compartilhado
const ecdh = crypto.createECDH('secp521r1');
ecdh.generateKeys();

const senderPublicKeyBuffer = Buffer.from(senderPublicKey, 'base64'); // Converte para Buffer corretamente

const sharedSecret = ecdh.computeSecret(senderPublicKeyBuffer);

// Função para descriptografar dados com AES-256
function decryptData(encryptedHex, ivHex, sharedSecret) {
  const key = crypto.createHash('sha256').update(sharedSecret).digest(); // Deriva chave AES
  const iv = Buffer.from(ivHex, 'hex');
  const encryptedData = Buffer.from(encryptedHex, 'hex');

  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decrypted = decipher.update(encryptedData);
  decrypted = Buffer.concat([decrypted, decipher.final()]);

  return decrypted.toString('utf8');
}

// Função para verificar assinatura digital
function verifySignature(encryptedData, signatureHex, senderPublicKey) {
  const verify = crypto.createVerify('sha256');
  verify.update(encryptedData);
  verify.end();
  return verify.verify(senderPublicKey, Buffer.from(signatureHex, 'hex'));
}

// Rota para receber o arquivo criptografado
app.post('/receber_ficheiro', (req, res) => {
  const { encryptedData, iv, signature } = req.body;

  if (!encryptedData || !iv || !signature) {
    return res.status(400).send('Dados incompletos.');
  }

  try {
    console.log('Verificando assinatura...');
    const isValidSignature = verifySignature(encryptedData, signature, senderPublicKey);

    if (!isValidSignature) {
      return res.status(400).send('Assinatura inválida.');
    }

    console.log('Descriptografando Ficheiro...');
    const decryptedData = decryptData(encryptedData, iv, sharedSecret);

    console.log('Ficheiro recebido e descriptografado com sucesso!');
    res.json({ message: 'Ficheiro processado!', decryptedData });
  } catch (error) {
    console.error('Erro ao processar o Ficheiro:', error);
    res.status(500).send('Erro ao processar o ficheiro.');
  }
});

// Inicia o servidor
app.listen(port, () => {
  console.log(`Servidor rodando em http://localhost:${port}`);
});
