const elliptic = require('elliptic');
const ec = new elliptic.ec('secp256k1');
const sha3 = require('js-sha3');

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
        publicKey: pubKey.encodeCompressed("hex")
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

function signAMessage(msg, nonce = Date.now()) {
    const messageAsJson = {
        "message": msg,
        "nonce": nonce
    };
    const messageInStr = JSON.stringify(messageAsJson);
    let msgHash = sha3.keccak256(messageInStr);
    let privKey = keyPair.getPrivate("hex");
    let signature = ec.sign(msgHash, privKey, "hex", {
        canonical: true
    });
    console.log(`Msg: ${messageInStr}`);
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
        r: signature.r.toString("hex"),
        s: signature.s.toString("hex"),
        nonce: nonce
    }
}

function verifySignedMessage(pubKey, msg, nonce, r, s) {
    const key = ec.keyFromPublic(pubKey, 'hex');
    const signature = {
        r: r,
        s: s
    };
    const messageAsJson = {
        "message": msg,
        "nonce": parseInt(nonce)
    };
    const messageInStr = JSON.stringify(messageAsJson);
    let msgHash = sha3.keccak256(messageInStr);
    console.log(`Msg: ${messageInStr}`);
    console.log(`Msg hash: ${msgHash}`);
    console.log("Signature:", signature);

    let validSig = key.verify(msgHash, signature);
    console.log("Signature valid?", validSig);
    return validSig;
}

module.exports = {
    generate: generate,
    getPublicKey: getPublicKey,
    signAMessage: signAMessage,
    verifySignedMessage: verifySignedMessage
}