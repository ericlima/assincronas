const fs = require('fs');
const path = require('path');
const axios = require('axios');
const crypto = require('crypto');

// Caminho do arquivo a ser enviado
const FILE_PATH = path.join(__dirname, 'historia.txt'); // Altere conforme necessário

// Caminhos das chaves
const PUBLIC_KEY_PATH = path.join(__dirname, '..', 'public-key.base64'); // Caminho correto para chave pública do servidor
const PRIVATE_KEY_PATH = path.join(__dirname, '..', 'private-key.base64'); // Caminho correto para chave privada do cliente

// Carrega a chave pública do servidor e converte para Buffer (Base64)
const recipientPublicKey = Buffer.from(fs.readFileSync(PUBLIC_KEY_PATH, 'utf8').trim(), 'base64');

//  Carrega a chave privada corretamente (Base64 -> Buffer)
const privateKeyBase64 = fs.readFileSync(PRIVATE_KEY_PATH, 'utf8').trim();
const privateKeyBuffer = Buffer.from(privateKeyBase64, 'base64');

// Converte o Buffer para uma chave privada utilizável
const privateKey = crypto.createPrivateKey({
  key: privateKeyBuffer,
  format: 'der', // DER porque a chave está em Base64
  type: 'pkcs8', // PKCS8 é o formato esperado para ECDSA
});

// Gera um par de chaves ECDH para calcular o segredo compartilhado
const ecdh = crypto.createECDH('secp521r1');
ecdh.generateKeys();

// Calcula o segredo compartilhado com a chave pública do servidor
const sharedSecret = ecdh.computeSecret(recipientPublicKey);

// **Função para criptografar dados usando AES-256**
function encryptData(data, sharedSecret) {
  const key = crypto.createHash('sha256').update(sharedSecret).digest(); // Deriva chave AES
  const iv = crypto.randomBytes(16); // Vetor de Inicialização (IV)

  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(data);
  encrypted = Buffer.concat([encrypted, cipher.final()]);

  return {
    iv: iv.toString('hex'),
    encryptedData: encrypted.toString('hex')
  };
}

// **Função para assinar os dados com a chave privada**
function signData(data, privateKey) {
  const sign = crypto.createSign('sha256');
  sign.update(data);
  sign.end();
  return sign.sign(privateKey, 'hex'); // Retorna assinatura em HEX
}

// ** Lê o arquivo, criptografa e envia para o servidor**
async function sendEncryptedFile() {
  try {
    console.log(` Lendo o arquivo: ${FILE_PATH}`);
    const fileBuffer = fs.readFileSync(FILE_PATH);

    console.log(' Criptografando o arquivo...');
    const { encryptedData, iv } = encryptData(fileBuffer, sharedSecret);

    console.log('Assinando os dados...');
    const signature = signData(encryptedData, privateKey);

    console.log('Enviando arquivo criptografado para o servidor...');
    const response = await axios.post('http://localhost:6000/receber_ficheiro', {
      encryptedData,
      iv,
      signature
    });

    console.log('Resposta do servidor:', response.data);
  } catch (error) {
    console.error('Erro ao enviar o arquivo:', error.message);
  }
}

// ** Executa o envio**
sendEncryptedFile();
