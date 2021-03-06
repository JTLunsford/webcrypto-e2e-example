#!/usr/bin/env node

'use strict';
//https://github.com/diafygi/webcrypto-examples#rsa-oaep---exportkey
const Hapi = require('hapi');

var WebCrypto = require("node-webcrypto-ossl");

var webcrypto = new WebCrypto({
    directory: "key_storage"
})

var keyStorage = webcrypto.keyStorage;

const crypto = webcrypto.subtle;

let encryptingKeysPromise = crypto.generateKey({
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: {
                name: "SHA-256"
            }
        },
        true, ['encrypt', 'decrypt']
    )
    .then(keys => {
        let {
            privateKey,
            publicKey
        } = keys;

        return new Promise((resolve, reject) => {
            try {
                crypto.exportKey('jwk', publicKey)
                    .then(exportedKey => {
                        //console.log(exportedKey);
                        resolve({
                            privateKey: privateKey,
                            publicKey: publicKey,
                            exportedKey: exportedKey
                        })
                    })
                    .catch((reason) => {
                        console.log('Handle rejected promise (' + reason + ') here.');
                    });
            }
            catch (e) {
                console.error(e);
            }
        });
    })
    .then(keys => {
        server.register(require('inert'), (err) => {

            if (err) {
                throw err;
            }

            server.route({
                method: 'GET',
                path: '/',
                handler: function(req, res) {
                    res.file('./client/index.html');
                }
            });
            server.route({
                method: 'GET',
                path: '/main.js',
                handler: function(req, res) {
                    res.file('./client/main.js');
                }
            });
        });

        server.route({
            method: 'POST',
            path: '/handshake',
            handler: function(req, res) {
                crypto.importKey(
                        'jwk',
                        JSON.parse(req.payload), {
                            name: "RSA-OAEP",
                            hash: {
                                name: "SHA-256"

                            },
                        },
                        false, ['encrypt', 'decrypt']
                    )
                    .then(cpk => {
                        return new Promise((resolve, reject) => {
                            symmetricKey(str2ab(JSON.stringify(keys.exportedKey)))
                                .then(encryptedServerPublicKeyAndExportedSymKey => {
                                    resolve({
                                        encryptedServerPublicKeyAndExportedSymKey: encryptedServerPublicKeyAndExportedSymKey,
                                        cpk: cpk
                                    });
                                });
                        })

                    })
                    .then(data => {
                        let encSymKey = crypto.encrypt({
                                    name: 'RSA-OAEP'
                                },
                                data.cpk,
                                data.encryptedServerPublicKeyAndExportedSymKey.exportedSymKey
                            )
                            .then(clientEncryptedSymKey => {
                                let x = base64ArrayBuffer(data.encryptedServerPublicKeyAndExportedSymKey.iv);
                                let test2 = new Uint8Array(data.encryptedServerPublicKeyAndExportedSymKey.cipher);
                                //console.log(test2.toString());
                                res(x + base64ArrayBuffer(appendBuffer(clientEncryptedSymKey, data.encryptedServerPublicKeyAndExportedSymKey.cipher)));
                            });

                    });
            }
        });

        server.route({
            method: 'POST',
            path: '/data',
            handler: function(req, res) {

                decryptMessage(keys.privateKey, req.payload)
                    .then(sensitiveClientDataStr => {
                        //console.log(sensitiveClientDataStr);
                        return JSON.parse(ab2str(sensitiveClientDataStr.payload));

                    })
                    .then(sensitiveClientData => {
                        //console.log(sensitiveClientData);
                        crypto.importKey(
                                'jwk',
                                sensitiveClientData.clientpublicKey, {
                                    name: "RSA-OAEP",
                                    hash: {
                                        name: "SHA-256"

                                    },
                                },
                                false, ['encrypt', 'decrypt']
                            )
                            .then(cpk => {
                                return new Promise((resolve, reject) => {
                                    symmetricKey(str2ab(JSON.stringify(require('./MOCK_DATA.json'))))
                                        .then(encData => {
                                            resolve({
                                                encData: encData,
                                                cpk: cpk
                                            });
                                        });
                                })

                            })
                            .then(data => {
                                let encSymKey = crypto.encrypt({
                                            name: 'RSA-OAEP'
                                        },
                                        data.cpk,
                                        data.encData.exportedSymKey
                                    )
                                    .then(clientEncryptedSymKey => {
                                        let x = base64ArrayBuffer(data.encData.iv);
                                        //console.log('cipher',new Uint8Array(data.encData.cipher).toString());
                                        res(x + base64ArrayBuffer(appendBuffer(clientEncryptedSymKey, data.encData.cipher)));
                                    });

                            });
                    });
            }
        });


        server.start((err) => {

            if (err) {
                throw err;
            }
            console.log(`Server running at: ${server.info.uri}`);
        });

    })
    
const server = new Hapi.Server();
server.connection({
    port: process.env.PORT,
    host: process.env.HOST
});

function decryptMessage(key, data) {
    if (data.substring(data.length - 2) === "==")
        data = data.substring(0, data.length - 2);
    if (data.substring(data.length - 1) === "=")
        data = data.substring(0, data.length - 1);
    let ab = Base64Binary.decodeArrayBuffer(data);
    let ivab = ab.slice(0, 16);
    let iv = new Uint8Array(ivab);
    //console.log('iv',iv.toString());
    let abSymKey = ab.slice(18, 256 + 18);
    let abSymKeyArray = new Uint8Array(abSymKey);
    //console.log('symkey', abSymKeyArray.toString());
    let payload = ab.slice(256 + 18);
    let payloadArray = new Uint8Array(payload);
    //console.log('payload',payloadArray.toString());
    return new Promise((resolve, reject) => {
        //console.log(1);
        crypto.decrypt({
                    name: "RSA-OAEP"
                },
                key,
                abSymKey
            )
            .then(rawSymKey => {
                let test3 = new Uint8Array(rawSymKey);
                //console.log('symkey',test3);
                crypto.importKey(
                        "raw",
                        rawSymKey, {
                            name: "AES-GCM",
                        },
                        true, ["encrypt", "decrypt"]
                    )
                    .then(symKey => {
                        //console.log(3, symKey);
                        return crypto.decrypt({
                                name: "AES-GCM",
                                iv: iv,
                            },
                            symKey,
                            payload
                        )
                    })
                    .then(decryptedPayload => {
                        //console.log(4, new Uint8Array(decryptedPayload));
                        resolve({
                            payload: decryptedPayload
                        })
                    })
                    .catch(err => {
                        console.log(err);
                    })

            })
            .catch(err => {
                console.log(err);
            })
    });
}

function symmetricKey(ab) {
    return new Promise((resolve, reject) => {
        let symKeyPromise = crypto.generateKey({
                    name: "AES-GCM",
                    length: 128
                },
                true, ["encrypt", "decrypt"]
            )
            .then(key => {
                crypto.exportKey('raw', key)
                    .then(exportedSymKey => {
                        let iv = webcrypto.getRandomValues(new Uint8Array(16));
                        crypto.encrypt({
                                    name: 'AES-GCM',
                                    iv: iv
                                },
                                key,
                                ab)
                            .then(enc => {
                                resolve({
                                    exportedSymKey: exportedSymKey,
                                    cipher: enc,
                                    iv: iv
                                });
                            })
                    });
            });
    });

}

/**
* Very angry the below functions are not already built into es6+
* atob() and btoa() do not exist in Node... so i didn't use those
* stole most of these from SO :)
**/

function ab2str(buf) {
    return String.fromCharCode.apply(null, new Uint16Array(buf));
}

function str2ab(str) {
    var buf = new ArrayBuffer(str.length * 2); // 2 bytes for each char
    var bufView = new Uint16Array(buf);
    for (var i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}

var appendBuffer = function(buffer1, buffer2) {
    var tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
    tmp.set(new Uint8Array(buffer1), 0);
    tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
    return tmp.buffer;
};

function base64ArrayBuffer(arrayBuffer) {
    var base64 = ''
    var encodings = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='

    var bytes = new Uint8Array(arrayBuffer)
    var byteLength = bytes.byteLength
    var byteRemainder = byteLength % 3
    var mainLength = byteLength - byteRemainder

    var a, b, c, d
    var chunk

    // Main loop deals with bytes in chunks of 3
    for (var i = 0; i < mainLength; i = i + 3) {
        // Combine the three bytes into a single integer
        chunk = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2]

        // Use bitmasks to extract 6-bit segments from the triplet
        a = (chunk & 16515072) >> 18 // 16515072 = (2^6 - 1) << 18
        b = (chunk & 258048) >> 12 // 258048   = (2^6 - 1) << 12
        c = (chunk & 4032) >> 6 // 4032     = (2^6 - 1) << 6
        d = chunk & 63 // 63       = 2^6 - 1

        // Convert the raw binary segments to the appropriate ASCII encoding
        base64 += encodings[a] + encodings[b] + encodings[c] + encodings[d]
    }

    // Deal with the remaining bytes and padding
    if (byteRemainder == 1) {
        chunk = bytes[mainLength]

        a = (chunk & 252) >> 2 // 252 = (2^6 - 1) << 2

        // Set the 4 least significant bits to zero
        b = (chunk & 3) << 4 // 3   = 2^2 - 1

        base64 += encodings[a] + encodings[b] + '=='
    }
    else if (byteRemainder == 2) {
        chunk = (bytes[mainLength] << 8) | bytes[mainLength + 1]

        a = (chunk & 64512) >> 10 // 64512 = (2^6 - 1) << 10
        b = (chunk & 1008) >> 4 // 1008  = (2^6 - 1) << 4

        // Set the 2 least significant bits to zero
        c = (chunk & 15) << 2 // 15    = 2^4 - 1

        base64 += encodings[a] + encodings[b] + encodings[c] + '='
    }

    return base64
}

var Base64Binary = {
    _keyStr: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",

    /* will return a  Uint8Array type */
    decodeArrayBuffer: function(input) {
        var bytes = (input.length / 4) * 3;
        var ab = new ArrayBuffer(bytes);
        this.decode(input, ab);

        return ab;
    },

    removePaddingChars: function(input) {
        var lkey = this._keyStr.indexOf(input.charAt(input.length - 1));
        if (lkey == 64) {
            return input.substring(0, input.length - 1);
        }
        return input;
    },

    decode: function(input, arrayBuffer) {
        //get last chars to see if are valid
        input = this.removePaddingChars(input);
        input = this.removePaddingChars(input);

        var bytes = parseInt((input.length / 4) * 3, 10);

        var uarray;
        var chr1, chr2, chr3;
        var enc1, enc2, enc3, enc4;
        var i = 0;
        var j = 0;

        if (arrayBuffer)
            uarray = new Uint8Array(arrayBuffer);
        else
            uarray = new Uint8Array(bytes);

        input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");

        for (i = 0; i < bytes; i += 3) {
            //get the 3 octects in 4 ascii chars
            enc1 = this._keyStr.indexOf(input.charAt(j++));
            enc2 = this._keyStr.indexOf(input.charAt(j++));
            enc3 = this._keyStr.indexOf(input.charAt(j++));
            enc4 = this._keyStr.indexOf(input.charAt(j++));

            chr1 = (enc1 << 2) | (enc2 >> 4);
            chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
            chr3 = ((enc3 & 3) << 6) | enc4;

            uarray[i] = chr1;
            if (enc3 != 64) uarray[i + 1] = chr2;
            if (enc4 != 64) uarray[i + 2] = chr3;
        }

        return uarray;
    }
}