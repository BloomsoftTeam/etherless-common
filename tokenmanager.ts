import { writeFileSync, readFileSync } from 'fs';
import _sodium  = require("libsodium-wrappers");
const _tokenByteSize = 64;

class PaymentToken {
    token: string;
    proof: string;
    constructor(token: string, proof: string) {
        this.token = token;
        this.proof = proof;
    }
}

/** usage
on client generate token = newToken()
send token.proof via insecure channel
authenticate via secure channel with token.token

on server receive via insecure channel the receivedProof
when authenticating the client verifyToken(new PaymentToken(receivedToken, receivedProof))
*/

function newToken() { return new Promise((resolve, reject) => {_sodium.ready.then(() => { const sodium = _sodium;
    let random_token = sodium.to_base64(sodium.randombytes_buf(_tokenByteSize));
    let token_proof  = sodium.to_base64(sodium.crypto_hash(random_token));
    resolve(new PaymentToken(random_token, token_proof));
}).catch(reject);});}

function verifyToken(_token: PaymentToken) { return new Promise((resolve, reject) => {_sodium.ready.then(() => { const sodium = _sodium;
    let testProof = sodium.to_base64(sodium.crypto_hash(_token.token));
    resolve(testProof === _token.proof);
}).catch(reject);});}

/** test
newToken().then((_test: PaymentToken) => {
    console.log(_test);
    verifyToken(_test).then(console.log).catch(console.error);
}).catch(console.error);
*/


