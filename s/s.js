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

// Rota simples
app.get('/', (req, res) => {
    res.send('Servidor seguro com Perfect Forward Secrecy (PFS)!');
});

// Rota para obter a chave publica do servidor
app.get('/hello', (req, res) => {
    console.log('Chamada para /hello');
    const servidor = crypto.createECDH('secp521r1');
    const servidorKey = servidor.generateKeys();
    res.send(servidorKey.toString('base64'));;
});

app.post('/enviar_ficheiro', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'Nenhum arquivo enviado.' });
    }

    console.log('Arquivo recebido:', req.file.originalname);
    console.log('Caminho salvo:', req.file.path);

    const newPath = path.join(__dirname, 'uploads', req.file.originalname);
    fs.renameSync(req.file.path, newPath);

    res.json({ message: 'Arquivo recebido com sucesso!', filePath: newPath });
    
});

// Criar servidor HTTPS com PFS
https.createServer(options, app).listen(PORT, () => {
    console.log(`Servidor HTTPS com PFS rodando em https://localhost:${PORT}`);
});
