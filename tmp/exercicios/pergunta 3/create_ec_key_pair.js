// This code creates an EC key pair and displays it in the console, in hex
// Author Osvaldo Santos oas@ipcb.pt

const crypto = require ("crypto");

// Just for fun, let's take a look of all the curves that are supported in node
// we don't need to print the list of curves to use it, this is just informational
const curves = crypto.getCurves();

// Printing the list of all the algorithms 
console.log("The list of all elliptic curves are as follows: ", curves);

// in this example we will use the secp128r2 curve
const keyPair = crypto.createECDH('secp128r2');
keyPair.generateKeys();

const publicKey=keyPair.getPublicKey();
const privateKey=keyPair.getPrivateKey();

// show the public key in hex
console.log("\r\nPublic Key (hex): ", publicKey.toString('hex'));

// show the private key in hex
console.log("\r\nPrivate Key (hex):", privateKey.toString('hex'));




