const elliptic = require('elliptic');
const ec = new elliptic.ec('secp256k1');
const sha256 = require('js-sha256');
const stringify = require("canonical-json");

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

function getPublicKey(priv) {
    keyPair = ec.keyFromPrivate(priv, "hex");
    let pubKey = keyPair.getPublic();
    console.log("Public key :", pubKey.encode("hex").substr(2));
    console.log("Public key (compressed):",
        pubKey.encodeCompressed("hex"));

    console.log();
    return {
        publicKey: pubKey.encodeCompressed("hex")
    }
};

function signAMessage(msg, nonce = Date.now()) {
    const messageAsJson = JSON.parse(msg);
        messageAsJson["userNonce"] = nonce;
        const jsonWithoutWhitespace = removeWhitespace(messageAsJson);
        const messageInStr = stringify(jsonWithoutWhitespace);
        let msgHash = sha256(messageInStr);
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

        messageAsJson.signature = {
            r: signature.r.toString("hex", 64),
            s: signature.s.toString("hex", 64)
        };
        messageAsJson.userNonce = nonce;
        return messageAsJson;
}

function verifySignedMessage(pubKey, msg, nonce, r, s) {
    const key = ec.keyFromPublic(pubKey, 'hex');
    const signature = {
        r: r,
        s: s
    };
    const messageAsJson = JSON.parse(msg);
    messageAsJson["userNonce"] = nonce;
    const jsonWithoutWhitespace = removeWhitespace(messageAsJson);
    console.log(jsonWithoutWhitespace);
    const messageInStr = stringify(jsonWithoutWhitespace);
    let msgHash = sha256(messageInStr);
    console.log(`Msg: ${messageInStr}`);
    console.log(`Msg hash: ${msgHash}`);
    console.log("Signature:", signature);

    let validSig = key.verify(msgHash, signature);
    console.log("Signature valid?", validSig);
    return validSig;
}

function removeWhitespace(res) {
    return JSON.parse(JSON.stringify(res));
}

module.exports = {
    generate: generate,
    getPublicKey: getPublicKey,
    signAMessage: signAMessage,
    verifySignedMessage: verifySignedMessage
}
