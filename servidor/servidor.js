const express = require('express');
const crypto = require('crypto');
const https = require('https');
const multer = require('multer');
const fs = require('fs');
const path = require('path');

// Carregar certificados SSL
const options = {
    key: fs.readFileSync(path.join(__dirname, 'key.pem')),
    cert: fs.readFileSync(path.join(__dirname, 'cert.pem')),
    ciphers: 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384',
    honorCipherOrder: true,
    minVersion: 'TLSv1.2'
};

// Configurar armazenamento para uploads
const upload = multer({ dest: 'uploads/' });

const app = express();
const PORT = 6000;

const decryptFile = async (inputPath, outputPath, secretKey) => {
    const key = deriveKey(secretKey); // Gerar chave AES-256

    // Ler o conteúdo do arquivo criptografado
    const fileContent = fs.readFileSync(inputPath);

    // Extrair IV, dados criptografados e tag de autenticação
    const iv = fileContent.slice(0, 16);
    const encryptedData = fileContent.slice(16, -16);
    const authTag = fileContent.slice(-16);

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag); // Definir a tag de autenticação

    try {
        const decryptedData = Buffer.concat([decipher.update(encryptedData), decipher.final()]);
        fs.writeFileSync(outputPath, decryptedData);

        console.log('Arquivo descriptografado:', outputPath);
    } catch (error) {
        console.error('Erro ao descriptografar o arquivo:', error.message);
    }
}

const deriveKey = (secret) => {
    return crypto.createHash('sha256').update(secret).digest();
}

// Rota simples
app.get('/', (req, res) => {
    res.send('Servidor seguro com Perfect Forward Secrecy (PFS)!');
});

// Rota para obter a chave publica do servidor
app.get('/obtem_chave', async (req, res) => {
    console.log('Chamada para /obtem_chave');
    const servidor = crypto.createECDH('secp521r1');
    const servidorKey = servidor.generateKeys();
    res.send(servidorKey.toString('base64'));
});

app.post('/receber_ficheiro', upload.single('file'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'Nenhum ficheiro enviado.' });
    }

    console.log('Ficheiro recebido:', req.file.originalname);
    console.log('Caminho salvo:', req.file.path);

    const clientSecretBase64 = req.headers['x-client-secret'];

    console.log('Chave secreta do cliente:', clientSecretBase64);

    const clientSecret = Buffer.from(clientSecretBase64, 'base64');

    const newPath = path.join(__dirname, 'uploads', req.file.originalname);
    fs.renameSync(req.file.path, newPath);

    res.json({ message: 'Arquivo recebido com sucesso!', filePath: newPath });
    const decryptedFilePath = path.join(__dirname, 'historia_decrypted.txt');
    await decryptFile(newPath, decryptedFilePath, clientSecret);
});

// Criar servidor HTTPS com PFS
https.createServer(options, app).listen(PORT, () => {
    console.log(`Servidor HTTPS com PFS rodando em https://localhost:${PORT}`);
});
