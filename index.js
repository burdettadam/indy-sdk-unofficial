var  ursa = require('./lib/ursa/pkg/ursa.js');
var pack = require('pack-unpack');
var sign = require('sign-attr');
var _ = require('lodash');

function valuesBuilder(credValues,hiddenAttrs,commitmentAttrs,pathToEncodedValue,pathToBlindingFactorValue){
    if (pathToEncodedValue === undefined) {
        pathToEncodedValue = ['encoded'];
    }
    if (pathToBlindingFactorValue === undefined) {
        pathToBlindingFactorValue = ['blinding_factor'];
    }
    var valuesBuilder = new ursa.CredentialValues();
    for (key in hiddenAttrs ) {
        valuesBuilder.add_hidden(key, _.get(hiddenAttrs[key],pathToEncodedValue));
    }
    for (key in credValues ) {
        valuesBuilder = ursa.add_known(valuesBuilder,key, _.get(credValues[key],pathToEncodedValue));
    }
    for (key in commitmentAttrs ) {
        valuesBuilder.add_commitment(key, _.get(commitmentAttrs[key],pathToEncodedValue),_.get(commitmentAttrs[key],pathToBlindingFactorValue));
    }
    //TODO: check if we need to use add_master_secret.... its just a hidden value.
    return valuesBuilder; 
}

module.exports = {
    unpack_message: function(enc_message,to_keys){
        return pack.unpack_message(enc_message,to_keys);
    },
    pack_message: function(enc_message, to_keys, from_keys){
        return pack.pack_message(enc_message, to_keys, from_keys);
    },
    sign: function(attr,keys){
        return sign.sign_attr(attr,keys);
    },
    verify: function(signed_attr){
        return sign.verify_attr(signed_attr);
    },

    nonce: function(){
        var nonce = new ursa.Nonce();
        return nonce;
        },
// issuer
    _schemaBuilder: function(attrNames){
        var schemaBuilder = new ursa.CredentialSchema();
        for (var i = 0, len = attrNames.length; i < len; i++) {
            console.log(attrNames[i]);
            schemaBuilder.add_attr(attrNames[i]); 
        }
        return schemaBuilder;
    },
    _nonSchemaBuilder: function (nonAttrNames){
        var nonSchemaBuilder = new ursa.NonCredentialSchema();
        for (var i = 0, len = nonAttrNames.length; i < len; i++) {
            nonSchemaBuilder.add_attr(nonAttrNames[i]); 
        }
        return nonSchemaBuilder;
    },
    _credentialValuesBuilder: valuesBuilder,
    _newCredDef: ursa.Issuer.newCredentialDef,
    credentialDef:  function(attrNames,nonAttrNames,supportRevocation){
        var schema = schemaBuilder(attrNames); 
        var nonSchema = nonSchemaBuilder(nonAttrNames);
        return ursa.Issuer.newCredentialDef(schema,nonSchema,supportRevocation);
    },
    revocationRegistry: function(credDef,maxCredNum,issuanceByDefault){
        pubKeyPtr = ref.alloc(ref.types.void);
        buildPubKeyFromParts(credDef.value.primary,credDef.value.revocation,pubKeyPtr);
        var revKeyPubPtr = ref.alloc(ref.types.void), revKeyPrivPtr = ref.alloc(ref.types.void), revRegPtr = ref.alloc(ref.types.void), revTailsGeneratorPtr = ref.alloc(ref.types.void);
        revKeyPubPtr,revKeyPrivPtr,revRegPtr,revTailsGeneratorPtr = cl.ursa_cl_issuer_new_revocation_registry_def(pubKeyPtr,maxCredNum,issuanceByDefault);
        var revKeysPub = { accum_key : revKeyPubPtr.deref() };
        return [revKeysPub, revKeyPrivPtr.deref(), revRegPtr.deref(), revTailsGeneratorPtr.deref()];
    }, 
    credential: function(credDef, linkedSecret, credPrivKey,credIssuanceBlindingNonce,  
                            credRequest, credValues, revIdx, revRegDef, 
                            revReg, revKeyPriv,revTailsAccessor){

        var credentialValues = valuesBuilder(credValues, 
                                                {'link_secret':
                                                    {'raw': linkedSecret,
                                                     'encoded': linkedSecret}},
                                             []);
        /** example rust code
            if rev_idx.is_some() {

                CryptoIssuer::sign_credential_with_revoc(&cred_request.prover_did,
                                                         &cred_request.blinded_ms,
                                                         &cred_request.blinded_ms_correctness_proof,
                                                         cred_issuance_blinding_nonce,
                                                         &cred_request.nonce,
                                                         &credential_values,
                                                         &credential_pub_key,
                                                         &cred_priv_key,
                                                         rev_idx,
                                                         rev_reg_def.value.max_cred_num,
                                                         rev_reg_def.value.issuance_type.to_bool(),
                                                         rev_reg,
                                                         rev_key_priv,
                                                         rev_tails_accessor)?
            } else {
                let (signature, correctness_proof) =
                    CryptoIssuer::sign_credential(&cred_request.prover_did,
                                                  &cred_request.blinded_ms,
                                                  &cred_request.blinded_ms_correctness_proof,
                                                  cred_issuance_blinding_nonce,
                                                  &cred_request.nonce,
                                                  &credential_values,
                                                  &credential_pub_key,
                                                  &cred_priv_key)?;
                (signature, correctness_proof, None)
            };

         */
        let res;
        if(!!revIdx){
            if(!revReg)throw new Error("RevocationRegistry not found");
            if(!revKeyPriv)throw new Error("RevocationKeyPrivate not found");
            if(!revRegDef)throw new Error("RevocationRegistryDefinitionValue not found");
            if(!revTailsAccessor)throw new Error("RevocationTailsAccessor not found");
            return ursa.Issuer.signCredentialWithRevocation();
        }else{
            return ursa.Issuer.signCredential();
        }
    },
    revoke: function(revReg, maxCredNum, revIdx, revTailsAccessor){
        //CryptoIssuer::revoke_credential(rev_reg, max_cred_num, rev_idx, rev_tails_accessor)?;
    }, 
    recovery: function(revReg, maxCredNum, revIdx, revTailsAccessor){
        //CryptoIssuer::recovery_credential(rev_reg, max_cred_num, rev_idx, rev_tails_accessor)?
    }, 
//Prover 
    link_secret: function(){
        return new ursa.MasterSecret();
    },
    createCredentialRequest: function(){},  
    createProof: function(){},  
    createRevocationState: function(){},  
    updateRevocationState: function(){},  
//verifier
    verifyProof: function(){

    },  
    //build_sub_proof_request
    
};  

