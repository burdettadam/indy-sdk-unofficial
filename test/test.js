var assert = require('assert');
var indy = require('../index.js')
describe('cl', function() {
  describe('_schemaBuilder', function() {
    it('_schemaBuilder should return a schema', function(){
      assert.equal(indy._schemaBuilder(['name','age']),['name','age']);
    });
  });
  describe('_nonSchemaBuilder', function() {
    it('_nonSchemaBuilder should return a nonschema', function(){
      assert.equal(indy._nonSchemaBuilder(['name','age']),['name','age'] );
    });
  });
  describe('_newCredDef', function() {});
  describe('_valuesBuilder', function() {});
  describe('_nonce', function() {});
  describe('_issuer', function() {
    describe('credentialDef', function() {});
    describe('revocationRegistry', function() {});
    describe('credential', function() {});
    describe('revoke', function() {});
    describe('recovery', function() {});
  });
  describe('prover', function() {
    describe('link_secret', function() {});
    describe('createCredentialRequest', function() {});
    describe('createProof', function() {});
    describe('createRevocationState', function() {});
    describe('updateRevocationState', function() {});
  });
  describe('verifier', function() {
    describe('verifyProof', function() {});
  });
});
describe('bls', function(){ });
