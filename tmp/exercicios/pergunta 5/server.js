// Server code example for ECDH key agreement with a remote client
// author Osvaldo Santos oas@ipcb.pt

// don't forget to: npm install express cors
const crypto = require('crypto')
var express = require('express')
const cors = require('cors');

// we are going to use express as the HTTP server
var app = express()
app.use(express.json());


// allow requests from everywhere (CORS policy)
// without this, it wouldn't be possible to make requests from other websites
app.use(cors({
    origin: '*'
}));

// this is the EC curve we are going to use
// the client must use the same curve
// in browsers, this curve is named 'P-384'
const curveType='secp384r1';

// Generate a EC key pair for this server
const serverEC = crypto.createECDH(curveType);
serverEC.generateKeys();

// get the public key, because it must be sent to clients
var publicKey = serverEC.getPublicKey();
var serverECpublicKey = publicKey.toString('hex');

console.log(`The server's EC public key is: ${serverECpublicKey}`);


// Wait for POST requests on /ecdh
app.post('/ecdh', function (req, res) {

  // if the client forgets to send the clientPublicKey parameter
  let response = 'You must send an HTTP parameter named clientPublicKey';

  let clientPublicKey = req.body.clientPublicKey;
  
  if (clientPublicKey != undefined) { // the client sent the required parameter
    // show the client's public key in the console
    console.log(`\r\nPOST received, clientPublicKey = ${clientPublicKey}`)

    // compute the shared secret key, using the server's private key and the client's public key
    let sharedSecretKey = serverEC.computeSecret(clientPublicKey,'hex');

    // convert to string in hex format
    let sharedSecretKeyHex = sharedSecretKey.toString('hex');
    
    //For a 256 bit shared key, we only need the first 64 hex digits
    sharedSecretKeyHex = sharedSecretKeyHex.slice(0, 64);

    // show the shared secret key in console
    console.log(`\r\nShared secret: ${sharedSecretKeyHex}`)

    response = {
        'serverPublicKey' : serverECpublicKey 
    }
  }

  // send the server's public key to the client, so that it can compute the shared key
  res.send(response);
})

app.listen(3000, function () {
  console.log('\r\necdh listening on port 3000!')
})