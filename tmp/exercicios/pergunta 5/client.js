// Client code example for ECDH key agreement with a remote server
// author Osvaldo Santos oas@ipcb.pt

const crypto = require('crypto')

// change this url to your own server
url = 'http://127.0.0.1:3000/ecdh'

// this is the EC curve we are going to use
// the server must use the same curve
// this curve is also known as 'P-384'
const curveType='secp384r1';

// Generate a EC key pair for this client
const clientEC = crypto.createECDH(curveType);
clientEC.generateKeys();

// get the public key, because it must be sent to the server
var publicKey = clientEC.getPublicKey();
var clientECpublicKey = publicKey.toString('hex');

console.log(`The client's EC public key is: ${clientECpublicKey}`);

dataToSendToServer = {
  'clientPublicKey' : clientECpublicKey 
}

// make the http request, sending the client's public key
// one way is to use fetch
fetch(url, {
  method: "POST",
  headers: {"Content-Type": "application/json"},
  body: JSON.stringify(dataToSendToServer),
})
  .then((response) => response.json())
  .then((data) => {
      let serverPublicKey = data.serverPublicKey;

      if (serverPublicKey != undefined) { // the server sent the required parameter
      
        // show the server's public key in the console
        console.log(`\r\nResponse received, serverPublicKey = ${serverPublicKey}`)

        // compute the shared secret key, using the client's private key and the server's public key
        let sharedSecretKey = clientEC.computeSecret(serverPublicKey,'hex');

        // convert to string in hex format
        let sharedSecretKeyHex = sharedSecretKey.toString('hex');
    
        //For a 256 bit shared key, we only need the first 64 hex digits
        sharedSecretKeyHex = sharedSecretKeyHex.slice(0, 64);

        // show the shared secret key in console
        console.log(`\r\nShared secret: ${sharedSecretKeyHex}`)
      }

  
  });
