let sha3 = require('js-sha3');
let elliptic = require('elliptic');
let ec = new elliptic.ec('secp256k1');

let keyPair;

function generate() {
    keyPair = ec.genKeyPair();
    let privKey = keyPair.getPrivate("hex");
    let pubKey = keyPair.getPublic();
    console.log(`Private key: ${privKey}`);
    console.log("Public key :", pubKey.encode("hex").substr(2));
    console.log("Public key (compressed):",
        pubKey.encodeCompressed("hex"));

    console.log();
    return {
        privateKey: privKey,
        publicKey: pubKey.encode("hex")
    }
};

function getPublicKey() {
    let privKey = keyPair.getPrivate("hex");
    let pubKey = keyPair.getPublic();
    console.log(`Private key: ${privKey}`);
    console.log("Public key :", pubKey.encode("hex").substr(2));
    console.log("Public key (compressed):",
        pubKey.encodeCompressed("hex"));

    console.log();
};

function signAMessage(msg) {
    let msgHash = sha3.keccak256(msg);
    let privKey = keyPair.getPrivate("hex");
    let signature = ec.sign(msgHash, privKey, "hex", {
        canonical: true
    });
    console.log(`Msg: ${msg}`);
    console.log(`Msg hash: ${msgHash}`);
    console.log("Signature:", signature);

    console.log();

    let hexToDecimal = (x) => ec.keyFromPrivate(x, "hex").getPrivate().toString(10);
    let pubKeyRecovered = ec.recoverPubKey(
        hexToDecimal(msgHash), signature, signature.recoveryParam, "hex");
    console.log("Recovered pubKey:", pubKeyRecovered.encodeCompressed("hex"));

    let validSig = ec.verify(msgHash, signature, pubKeyRecovered);
    console.log("Signature valid?", validSig);
    return {
        r: signature.r.toString(),
        s: signature.s.toString()
    }
}

module.exports = {
    generate: generate,
    getPublicKey: getPublicKey,
    signAMessage: signAMessage
}