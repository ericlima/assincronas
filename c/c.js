const fs = require('fs');
const path = require('path');
const axios = require('axios');
const crypto = require('crypto');
const https = require('https');

// Caminho do ficheiro a ser enviado
const FILE_PATH = path.join(__dirname, 'historia.txt');
const ENCRYPTED_FILE_PATH = path.join(__dirname, 'historia_encrypted.txt');

// Generate cliente's keys...
const cliente = crypto.createECDH('secp521r1');
const clienteKey = cliente.generateKeys();

// Criar agente HTTPS com suporte a TLS 1.2
const httpsAgent = new https.Agent({
    rejectUnauthorized: false, 
    cert: fs.readFileSync(path.join(__dirname, 'cert.pem')), // Certificado do servidor
    key: fs.readFileSync(path.join(__dirname, 'key.pem')), // Chave privada do servidor
    ciphers: 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384',
    honorCipherOrder: true,
    minVersion: 'TLSv1.2'
});

// Função para derivar a chave AES-256 a partir de `clienteSecret`
const deriveKey = (secret) => {
    return crypto.createHash('sha256').update(secret).digest();
}

// Função para criptografar o arquivo
const encryptFile = async (inputPath, outputPath, secretKey) => {
    const key = deriveKey(secretKey); // Gerar chave AES-256
    const iv = crypto.randomBytes(16); // Criar IV aleatório

    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const fileContent = fs.readFileSync(inputPath);

    const encryptedData = Buffer.concat([cipher.update(fileContent), cipher.final()]);
    const authTag = cipher.getAuthTag(); // Capturar tag de autenticação

    // Salvar IV + Encrypted Data + Auth Tag no arquivo de saída
    fs.writeFileSync(outputPath, Buffer.concat([iv, encryptedData, authTag]));

    console.log('Arquivo criptografado:', outputPath);
}

// Função para enviar o arquivo ao servidor
const sendEncryptedFile = async (clienteSecret) => {
    try {
        encryptFile(FILE_PATH, ENCRYPTED_FILE_PATH, clienteSecret);

        // Criar FormData e anexar o arquivo criptografado
        const formData = new FormData();
        formData.append('file', fs.createReadStream(ENCRYPTED_FILE_PATH));

        // Enviar para o servidor via POST
        const response = await axios.post('https://localhost:6000/enviar_ficheiro', 
            formData, {
            httpsAgent,
            headers: {
                'Content-Type': 'multipart/form-data'
            }
        });

        console.log('Resposta do servidor:', response.data);
    } catch (error) {
        console.error('Erro ao enviar o ficheiro:', error.message);
    }
}

(async () => {
    try {
        const response = await axios.get('https://localhost:6000/hello',{
            httpsAgent
        });
        const serverPublicKey = Buffer.from(response.data, 'base64');
        console.log('Chave pública do servidor:', serverPublicKey.toString('hex'));
        const clienteSecret = cliente.computeSecret(serverPublicKey);
        console.log('Chave secreta do cliente:', clienteSecret.toString('hex'));
        await sendEncryptedFile(clienteSecret);
    } catch (error) {
        console.error('Erro ao obter a chave pública do servidor:', error.message);
    }
})();

