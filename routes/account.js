var express = require('express');
var db = require('../db');
var cose2jwk = require('cose-to-jwk');
var jwk2pem = require('jwk-to-pem');
var cbor = require('cbor');
var base64url = require('base64url');
var jws = require('jws');
var x509 = require('@fidm/x509');
var router = express.Router();


router.get('/',
  require('connect-ensure-login').ensureLoggedIn(),
  function(req, res, next) {
    res.render('profile', { user: req.user });
  });

/* GET users listing. */
router.get('/new', function(req, res, next) {
  res.render('register');
});

router.post('/', function(req, res, next) {
  console.log('REGISTER!');
  console.log(req.headers);
  console.log(req.body);
  
  var user = {
    displayName: req.body.name,
    username: req.body.username
  };
  
  // FIXME: rename to users
  // use post to auto-assign an _id
  db.post(user, function callback(err, result) {
    console.log(err);
    console.log(result);
    
    if (err) { return next(err); }
    
    var opts = {
      challenge: '1234', // TODO: Make this random,
      rp: {
          name: "ACME Corporation"
      },
      user: {
        id: result.id,
        name: user.username,
        displayName: user.displayName
      },
      pubKeyCredParams: [
        {
          type: "public-key", alg: -7 // "ES256" IANA COSE Algorithms registry
        }
      ],
      attestation: 'direct'
    }
    
    res.json(opts);
  });
});



var USER_PRESENT = 0x01;
var ATTESTED_CREDENTIAL_INCLUDED = 0x40;
var EXTENSTION_DATA_INCLUDED = 0x80;

function parseMakeCredAuthData(buffer) {
  var i = 0;
  var rpIdHash = buffer.slice(i, i += 32);
  var flags = buffer.slice(i, i += 1);
  var signCount = buffer.slice(i, i += 4);
  
  console.log(flags)
  
  flags = flags[0]
  
  var authData = {
    rpIdHash: rpIdHash,
    flags: flags,
    signCount: signCount.readUInt32BE(0)
  };
  
  
  if (flags & USER_PRESENT) {
    console.log('USER PRESENT!')
  }
  
  if (flags & ATTESTED_CREDENTIAL_INCLUDED) {
    var aaguid = buffer.slice(i, i += 16);
    var credentialIdLength = buffer.slice(i, i += 2);
    credentialIdLength = credentialIdLength.readUInt16BE(0);
    
    console.log('CRED DATA INCLUDED!');
    console.log(credentialIdLength)
    
    var credentialId = buffer.slice(i, i += credentialIdLength);
    console.log(credentialId);
    console.log(base64url.encode(credentialId));
    
    // TODO: Determine lenght of this, so that extensions can be parsed, if included.
    var credentialPublicKey = buffer.slice(i);
    console.log(credentialPublicKey);
    
    authData.aaguid = aaguid;
    authData.credentialId = credentialId;
    authData.credentialPublicKey = credentialPublicKey;
  }
  
  return authData;
  
  
  /*
    let rpIdHash      = buffer.slice(0, 32);          buffer = buffer.slice(32);
    let flagsBuf      = buffer.slice(0, 1);           buffer = buffer.slice(1);
    let flags         = flagsBuf[0];
    let counterBuf    = buffer.slice(0, 4);           buffer = buffer.slice(4);
    let counter       = counterBuf.readUInt32BE(0);
    let aaguid        = buffer.slice(0, 16);          buffer = buffer.slice(16);
    let credIDLenBuf  = buffer.slice(0, 2);           buffer = buffer.slice(2);
    let credIDLen     = credIDLenBuf.readUInt16BE(0);
    let credID        = buffer.slice(0, credIDLen);   buffer = buffer.slice(credIDLen);
    let COSEPublicKey = buffer;

    return {rpIdHash, flagsBuf, flags, counter, counterBuf, aaguid, credID, COSEPublicKey}
  */
}

let ASN1toPEM = (pkBuffer) => {
    if (!Buffer.isBuffer(pkBuffer))
        throw new Error("ASN1toPEM: pkBuffer must be Buffer.")

    let type;
    if (pkBuffer.length == 65 && pkBuffer[0] == 0x04) {
        /*
            If needed, we encode rawpublic key to ASN structure, adding metadata:
            SEQUENCE {
              SEQUENCE {
                 OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
                 OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256)
              }
              BITSTRING <raw public key>
            }
            Luckily, to do that, we just need to prefix it with constant 26 bytes (metadata is constant).
        */
        
        pkBuffer = Buffer.concat([
            new Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex"),
            pkBuffer
        ]);

        type = 'PUBLIC KEY';
    } else {
        type = 'CERTIFICATE';
    }

    let b64cert = pkBuffer.toString('base64');

    let PEMKey = '';
    for(let i = 0; i < Math.ceil(b64cert.length / 64); i++) {
        let start = 64 * i;

        PEMKey += b64cert.substr(start, 64) + '\n';
    }

    PEMKey = `-----BEGIN ${type}-----\n` + PEMKey + `-----END ${type}-----\n`;
    
    return PEMKey
}

function saveToDB(body, userID, cb) {
  console.log('save to DB!');
  console.log(body);
  
  var response = body.response;
  
  //var clientData = JSON.parse(base64url.decode(response.clientDataJSON));
  //console.log(clientData);
  
  var response = body.response;
  var clientData = JSON.parse(base64url.decode(response.clientDataJSON));
  console.log(clientData);
  
  var attestationObject = cbor.decodeFirstSync(base64url.toBuffer(response.attestationObject));
  console.log(attestationObject);
  
  let authrDataStruct = parseMakeCredAuthData(attestationObject.authData);
  console.log(authrDataStruct)
  
  
  var pk = cbor.decodeAllSync(authrDataStruct.credentialPublicKey);
  console.log(pk);
  
  var jwk = cose2jwk(authrDataStruct.credentialPublicKey);
  console.log(jwk);
  
  var pem = jwk2pem(jwk);
  console.log(pem);
  
  
  var authnr = {
    externalID: body.id,
    publicKey: pem,
    userID: userID
  };
  
  
  switch (attestationObject.fmt) {
  case 'none':
    console.log('NONE!');
    break;
  case 'fido-u2f':
    console.log('FIDO U2F!!!');
    let PEMCertificate = ASN1toPEM(attestationObject.attStmt.x5c[0]);
    console.log(PEMCertificate);
    var c = x509.Certificate.fromPEM(PEMCertificate);
    console.log(c);
    break;
  case 'tpm':
    console.log('TPM!');
    let TPMPEMCertificate = ASN1toPEM(attestationObject.attStmt.x5c[0]);
    console.log(TPMPEMCertificate);
    var c = x509.Certificate.fromPEM(TPMPEMCertificate);
    console.log(c);
    break;
  case 'android-safetynet':
    console.log('ANDROID SAFETY!!!');
    var obj = jws.decode(attestationObject.attStmt.response, { json: true });
    console.log(obj);
    break;
  }
  
  
  
  
  console.log(authnr)
  //return;
  
  db.post(authnr, function callback(err, result) {
    console.log(err);
    console.log(result);
  });
}

router.post('/credentials', function(req, res, next) {
  console.log('CREDENTIAL!');
  console.log(req.headers);
  console.log(req.body);
  
  var userID = req.header('X-User-ID');
  
  saveToDB(req.body, userID, function(err, result) {
    // TODO
  });
});

module.exports = router;
