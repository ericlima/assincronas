const crypto = require('crypto');

// Função para desencriptar dados usando a chave privada do servidor
function decryptData(encryptedData, iv, serverPrivateKey) {
  const key = crypto.createECDH('secp521r1');
  key.setPrivateKey(serverPrivateKey);
  const sharedSecret = key.computeSecret(privateKey);

  // Desencriptar dados usando o SHA-256 do segredo compartilhado
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(sharedSecret), Buffer.from(iv, 'hex'));
  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

// Função para verificar assinatura usando a chave pública do emissor
function verifySignature(data, signature, emitterPublicKey) {
  const hash = crypto.createHash('sha256').update(data).digest();
  try {
    const isValid = crypto.verify(null, hash, emitterPublicKey, Buffer.from(signature, 'hex'));
    return isValid;
  } catch (err) {
    return false;
  }
}

// Exemplo de uso
const encryptedData = '...'; // Dados criptografados recebidos do cliente
const iv = '...'; // IV recebido do cliente
const signature = '...'; // Assinatura recebida do cliente
const emitterPublicKey = '...'; // Chave pública do emissor dos dados

const decryptedData = decryptData(encryptedData, iv, serverPrivateKey);
const isSignatureValid = verifySignature(decryptedData, signature, emitterPublicKey);

console.log('Decrypted Data:', decryptedData);
console.log('Is Signature Valid:', isSignatureValid);
