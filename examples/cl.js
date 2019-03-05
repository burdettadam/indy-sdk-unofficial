const  ursa =  require('/c/Users/burdettadam/Documents/GitHub/MLURSA/libursa/pkg/ursa.js');
example = require('./examples');
const util = require('util')

console.log(ursa.nonceNew());
let ms = ursa.masterSecretNew();
console.log(ms);

console.log(example.ursaClSchemaBuilder(['name','age']));
console.log(example.ursaClNonSchemaBuilder(['not a name','not an age']));

console.log(util.inspect(example.ursaClCredentialValuesBuilder({'name': {'raw':'adam','encoded':'123456'},
                                                    'age': {'raw':12, 'encoded':'12'} },
                                                  {'link_secret':{'raw': ms.ms,'encoded':ms.ms}},
                                                  {'other cred': {'encoded' : '4567', 'blinding_factor': ursa.nonceNew()}}),{showHidden: false, depth: null}));
     

console.log(example.credentialDef(['name','age'],['not a name','not an age'], true));

//console.log(ursa.credentialDefNew(example.ursaClSchemaBuilder(['name','age']),
//                                  example.ursaClNonSchemaBuilder(['not a name','not an age']),
//                                  false));

//console.log(ursa.blsSignKey());
//console.log(ursa.secp256k1new());


/*var ed = ursa.ed25519New();
console.log(ed);
var keyPair = ursa.ed25519KeyPair(ed);
console.log(keyPair);
var sig = ursa.ed25519Sign(ed,"this is my string",keyPair[1]);
console.log(sig);
console.log(ursa.ed25519Verify(ed,"this is my string",sig,keyPair[0]));
console.log(ursa.ed25519Verify(ed,"this is not my string",sig,keyPair[0]));
console.log(ursa.ed25519GetPublicKey(ed,keyPair[1]));*/