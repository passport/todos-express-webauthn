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
  return;
  
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


//https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html

/*
saveToDB({
    "rawId": "hWzdFiPbOMQ5KNBsMhs-Zeh8F0iTHrH63YKkrxJFgjQ",
    "id": "hWzdFiPbOMQ5KNBsMhs-Zeh8F0iTHrH63YKkrxJFgjQ",
    "response": {
        "clientDataJSON": "ew0KCSJ0eXBlIiA6ICJ3ZWJhdXRobi5jcmVhdGUiLA0KCSJjaGFsbGVuZ2UiIDogIndrNkxxRVhBTUFacHFjVFlsWTJ5b3I1RGppeUlfYjFneTluRE90Q0IxeUdZbm1fNFdHNFVrMjRGQXI3QXhUT0ZmUU1laWdrUnhPVExaTnJMeEN2Vl9RIiwNCgkib3JpZ2luIiA6ICJodHRwczovL3dlYmF1dGhuLm9yZyIsDQoJInRva2VuQmluZGluZyIgOiANCgl7DQoJCSJzdGF0dXMiIDogInN1cHBvcnRlZCINCgl9DQp9",
        "attestationObject": "o2NmbXRjdHBtaGF1dGhEYXRhWQFnlWkIjx7O4yMpVANdvRDXyuORMFonUbVZu4_Xy7IpvdRFAAAAAAiYcFjK3EuBtuEw3lDcvpYAIIVs3RYj2zjEOSjQbDIbPmXofBdIkx6x-t2CpK8SRYI0pAEDAzkBACBZAQDF2m9Nk1e94gL1xVjNCjFW0lTy4K2atXkx-YJrdH3hrE8p1gcIdNzleRDhmERJnY5CRwM5sXDQIrUBq4jpwvTtMC5HGccN6-iEJAPtm9_CJzCmGhtw9hbF8bcAys94RhN9xLLUaajhWqtPrYZXCEAi0o9E2QdTIxJrcAfJgZOf33JMr0--R1BAQxpOoGRDC8ss-tfQW9ufZLWw4JUuz4Z5Jz1sbfqBYB8UUDMWoT0HgsMaPmvd7T17xGvB-pvvDf-Dt96vFGtYLEZEgho8Yu26pr5CK_BOQ-2vX9N4MIYVPXNhogMGGmKYqybhM3yhye0GdBpZBUd5iOcgME6uGJ1_IUMBAAFnYXR0U3RtdKZjdmVyYzIuMGNhbGc5__5jc2lnWQEAcV1izWGUWIs0DEOZNQGdriNNXo6nbrGDLzEAeswCK9njYGCLmOkHVgSyafhsjCEMZkQmuPUmEOMDKosqxup_tiXQwG4yCW9TyWoINWGayQ4vcr6Ys-l6KMPkg__d2VywhfonnTJDBfE_4BIRD60GR0qBzTarthDHQFMqRtoUtuOsTF5jedU3EQPojRA5iCNC2naCCZuMSURdlPmhlW5rAaRZVF41ZZECi5iFOM2rO0UpGuQSLUvr1MqQOsDytMf7qWZMvwT_5_8BF6GNdB2l2VzmIJBbV6g8z7dj0fRkjlCXBp8UG2LvTq5SsfugrRWXOJ8BkdMplPfl0mz6ssU_n2N4NWOCWQS2MIIEsjCCA5qgAwIBAgIQEyidpWZzRxOSMNfrAvV1fzANBgkqhkiG9w0BAQsFADBBMT8wPQYDVQQDEzZOQ1UtTlRDLUtFWUlELTE1OTFENEI2RUFGOThEMDEwNDg2NEI2OTAzQTQ4REQwMDI2MDc3RDMwHhcNMTgwNTIwMTYyMDQ0WhcNMjgwNTIwMTYyMDQ0WjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvQ6XK2ujM11E7x4SL34p252ncyQTd3-4r5ALQhBbFKS95gUsuENTG-48GBQwu48i06cckm3eH20TUeJvn4-pj6i8LFOrIK14T3P3GFzbxgQLq1KVm63JWDdEXk789JgzQjHNO7DZFKWTEiktwmBUPUA88TjQcXOtrR5EXTrt1FzGzabOepFann3Ny_XtxI8lDZ3QLwPLJfmk7puGtkGNaXOsRC7GLAnoEB7UWvjiyKG6HAtvVTgxcW5OQnHFb9AHycU5QdukXrP0njdCpLCRR0Nq6VMKmVU3MaGh-DCwYEB32sPNPdDkPDWyk16ItwcmXqfSBV5ZOr8ifvcXbCWUWwIDAQABo4IB5TCCAeEwDgYDVR0PAQH_BAQDAgeAMAwGA1UdEwEB_wQCMAAwbQYDVR0gAQH_BGMwYTBfBgkrBgEEAYI3FR8wUjBQBggrBgEFBQcCAjBEHkIAVABDAFAAQQAgACAAVAByAHUAcwB0AGUAZAAgACAAUABsAGEAdABmAG8AcgBtACAAIABJAGQAZQBuAHQAaQB0AHkwEAYDVR0lBAkwBwYFZ4EFCAMwSgYDVR0RAQH_BEAwPqQ8MDoxODAOBgVngQUCAwwFaWQ6MTMwEAYFZ4EFAgIMB05QQ1Q2eHgwFAYFZ4EFAgEMC2lkOjRFNTQ0MzAwMB8GA1UdIwQYMBaAFMISqVvO-lb4wMFvsVvdAzRHs3qjMB0GA1UdDgQWBBSv4kXTSA8i3NUM0q57lrWpM8p_4TCBswYIKwYBBQUHAQEEgaYwgaMwgaAGCCsGAQUFBzAChoGTaHR0cHM6Ly9hemNzcHJvZG5jdWFpa3B1Ymxpc2guYmxvYi5jb3JlLndpbmRvd3MubmV0L25jdS1udGMta2V5aWQtMTU5MWQ0YjZlYWY5OGQwMTA0ODY0YjY5MDNhNDhkZDAwMjYwNzdkMy8zYjkxOGFlNC0wN2UxLTQwNTktOTQ5MS0wYWQyNDgxOTA4MTguY2VyMA0GCSqGSIb3DQEBCwUAA4IBAQAs-vqdkDX09fNNYqzbv3Lh0vl6RgGpPGl-MYgO8Lg1I9UKvEUaaUHm845ABS8m7r9p22RCWO6TSEPS0YUYzAsNuiKiGVna4nB9JWZaV9GDS6aMD0nJ8kNciorDsV60j0Yb592kv1VkOKlbTF7-Z10jaapx0CqhxEIUzEBb8y9Pa8oOaQf8ORhDHZp-mbn_W8rUzXSDS0rFbWKaW4tGpVoKGRH-f9vIeXxGlxVS0wqqRm_r-h1aZInta0OOiL_S4367gZyeLL3eUnzdd-eYySYn2XINPbVacK8ZifdsLMwiNtz5uM1jbqpEn2UoB3Hcdn0hc12jTLPWFfg7GiKQ0hk9WQXsMIIF6DCCA9CgAwIBAgITMwAAAQDiBsSROVGXhwAAAAABADANBgkqhkiG9w0BAQsFADCBjDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjE2MDQGA1UEAxMtTWljcm9zb2Z0IFRQTSBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDE0MB4XDTE3MDIwMTE3NDAyNFoXDTI5MTIzMTE3NDAyNFowQTE_MD0GA1UEAxM2TkNVLU5UQy1LRVlJRC0xNTkxRDRCNkVBRjk4RDAxMDQ4NjRCNjkwM0E0OEREMDAyNjA3N0QzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9IwUMSiQUbrQR0NLkKR-9RB8zfHYdlmDB0XN_m8qrNHKRJ__lBOR-mwU_h3MFRZF6X3ZZwka1DtwBdzLFV8lVu33bc15stjSd6B22HRRKQ3sIns5AYQxg0eX2PtWCJuIhxdM_jDjP2hq9Yvx-ibt1IO9UZwj83NGxXc7Gk2UvCs9lcFSp6U8zzl5fGFCKYcxIKH0qbPrzjlyVyZTKwGGSTeoMMEdsZiq-m_xIcrehYuHg-FAVaPLLTblS1h5cu80-ruFUm5Xzl61YjVU9tAV_Y4joAsJ5QP3VPocFhr5YVsBVYBiBcQtr5JFdJXZWWEgYcFLdAFUk8nJERS7-5xLuQIDAQABo4IBizCCAYcwCwYDVR0PBAQDAgGGMBsGA1UdJQQUMBIGCSsGAQQBgjcVJAYFZ4EFCAMwFgYDVR0gBA8wDTALBgkrBgEEAYI3FR8wEgYDVR0TAQH_BAgwBgEB_wIBADAdBgNVHQ4EFgQUwhKpW876VvjAwW-xW90DNEezeqMwHwYDVR0jBBgwFoAUeowKzi9IYhfilNGuVcFS7HF0pFYwcAYDVR0fBGkwZzBloGOgYYZfaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVFBNJTIwUm9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAxNC5jcmwwfQYIKwYBBQUHAQEEcTBvMG0GCCsGAQUFBzAChmFodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRQTSUyMFJvb3QlMjBDZXJ0aWZpY2F0ZSUyMEF1dGhvcml0eSUyMDIwMTQuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQAKc9z1UUBAaybIVnK8yL1N1iGJFFFFw_PpkxW76hgQhUcCxNFQskfahfFzkBD05odVC1DKyk2PyOle0G86FCmZiJa14MtKNsiu66nVqk2hr8iIcu-cYEsgb446yIGd1NblQKA1C_28F2KHm8YRgcFtRSkWEMuDiVMa0HDU8aI6ZHO04Naj86nXeULJSZsA0pQwNJ04-QJP3MFQzxQ7md6D-pCx-LVA-WUdGxT1ofaO5NFxq0XjubnZwRjQazy_m93dKWp19tbBzTUKImgUKLYGcdmVWXAxUrkxHN2FbZGOYWfmE2TGQXS2Z-g4YAQo1PleyOav3HNB8ti7u5HpI3t9a73xuECy2gFcZQ24DJuBaQe4mU5I_hPiAa-822nPPL6w8m1eegxhHf7ziRW_hW8s1cvAZZ5Jpev96zL_zRv34MsRWhKwLbu2oOCSEYYh8D8DbQZjmsxlUYR_q1cP8JKiIo6NNJ85g7sjTZgXxeanA9wZwqwJB-P98VdVslC17PmVu0RHOqRtxrht7OFT7Z10ecz0tj9ODXrv5nmBktmbgHRirRMl84wp7-PJhTXdHbxZv-OoL4HP6FxyDbHxLB7QmR4-VoEZN0vsybb1A8KEj2pkNY_tmxHH6k87euM99bB8FHrW9FNrXCGL1p6-PYtiky52a5YQZGT8Hz-ZnxobTmhjZXJ0SW5mb1ih_1RDR4AXACIAC7xZ9N_ZpqQtw7hmr_LfDRmCa78BS2erCtbrsXYwa4AHABSsnz8FacZi-wkUkfHu4xjG8MPfmwAAAAGxWkjHaED549jznwUBqeDEpT-7xBMAIgALcSGuv6a5r9BwMvQvCSXg7GdAjdWZpXv6D4DH8VYBCE8AIgALAVI0eQ_AAZjNvrhUEMK2q4wxuwIFOnHIDF0Qljhf47RncHViQXJlYVkBNgABAAsABgRyACCd_8vzbDg65pn7mGjcbcuJ1xU4hL4oA5IsEkFYv60irgAQABAIAAAAAAABAMXab02TV73iAvXFWM0KMVbSVPLgrZq1eTH5gmt0feGsTynWBwh03OV5EOGYREmdjkJHAzmxcNAitQGriOnC9O0wLkcZxw3r6IQkA-2b38InMKYaG3D2FsXxtwDKz3hGE33EstRpqOFaq0-thlcIQCLSj0TZB1MjEmtwB8mBk5_fckyvT75HUEBDGk6gZEMLyyz619Bb259ktbDglS7PhnknPWxt-oFgHxRQMxahPQeCwxo-a93tPXvEa8H6m-8N_4O33q8Ua1gsRkSCGjxi7bqmvkIr8E5D7a9f03gwhhU9c2GiAwYaYpirJuEzfKHJ7QZ0GlkFR3mI5yAwTq4YnX8"
    }
});
*/

/*
saveToDB({
    "rawId": "qCXEfJ-dEoBlWqIl0iq2p_gj13HSg7r_MA7xOcOiO8RkCrYNmQHIjV9yhZVASr87cUsflo7DNuuvGsnrlTl1ig",
    "id": "qCXEfJ-dEoBlWqIl0iq2p_gj13HSg7r_MA7xOcOiO8RkCrYNmQHIjV9yhZVASr87cUsflo7DNuuvGsnrlTl1ig",
    "response": {
        "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJEa1hCdWRCa2wzTzBlTUV5SGZBTVgxT2tRbHV4c2hjaW9WU3dITVJMUlhtd044SXJldHg3cWJ0MWx3Y0p4d0FxWUU0SUxTZjVwd3lHMEhXSWtEekVMUT09Iiwib3JpZ2luIjoid2ViYXV0aG4ub3JnIiwiaGFzaEFsZyI6IlNIQS0yNTYifQ",
        "attestationObject": "o2hhdXRoRGF0YVjElWkIjx7O4yMpVANdvRDXyuORMFonUbVZu4_Xy7IpvdRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQKglxHyfnRKAZVqiJdIqtqf4I9dx0oO6_zAO8TnDojvEZAq2DZkByI1fcoWVQEq_O3FLH5aOwzbrrxrJ65U5dYqlAQIDJiABIVggh5OJfYRDzVGIowKqU57AnoVjjdmmjGi9zlMkjAVV9DAiWCDr0iSi0viIKNPMTIdN28gWNmkcwOr6DQx66MPff3Odm2NmbXRxYW5kcm9pZC1zYWZldHluZXRnYXR0U3RtdKJjdmVyaDEyNjg1MDIzaHJlc3BvbnNlWRSnZXlKaGJHY2lPaUpTVXpJMU5pSXNJbmcxWXlJNld5Sk5TVWxGYVdwRFEwRXpTMmRCZDBsQ1FXZEpTVmxyV1c4MVJqQm5PRFpyZDBSUldVcExiMXBKYUhaalRrRlJSVXhDVVVGM1ZrUkZURTFCYTBkQk1WVkZRbWhOUTFaV1RYaElha0ZqUW1kT1ZrSkJiMVJHVldSMllqSmtjMXBUUWxWamJsWjZaRU5DVkZwWVNqSmhWMDVzWTNwRmJFMURUVWRCTVZWRlFYaE5ZMUl5T1haYU1uaHNTVVZzZFdSSFZubGliVll3U1VWR01XUkhhSFpqYld3d1pWTkNTRTE2UVdWR2R6QjRUbnBGZVUxRVVYaE5la1UwVGtST1lVWjNNSGhQUkVWNVRVUk5kMDFFUVhkTlJFSmhUVWQzZUVONlFVcENaMDVXUWtGWlZFRnNWbFJOVWsxM1JWRlpSRlpSVVVsRVFYQkVXVmQ0Y0ZwdE9YbGliV3hvVFZKWmQwWkJXVVJXVVZGSVJFRXhUbUl6Vm5Wa1IwWndZbWxDVjJGWFZqTk5VazEzUlZGWlJGWlJVVXRFUVhCSVlqSTVibUpIVldkVFZ6VnFUVkp6ZDBkUldVUldVVkZFUkVKS2FHUklVbXhqTTFGMVdWYzFhMk50T1hCYVF6VnFZakl3ZDJkblJXbE5RVEJIUTFOeFIxTkpZak5FVVVWQ1FWRlZRVUUwU1VKRWQwRjNaMmRGUzBGdlNVSkJVVU5WYWpoM1dXOVFhWGhMWW1KV09ITm5XV2QyVFZSbVdDdGtTWE5HVkU5clowdFBiR2hVTUdrd1ltTkVSbHBMTW5KUGVFcGFNblZUVEZOV2FGbDJhWEJhVGtVelNFcFJXWFYxV1hkR2FtbDVLM2xyWm1GMFFVZFRhbEo2UmpGaU16RjFORE12TjI5SE5XcE5hRE5UTXpkaGJIZHFWV0k0UTFkcFZIaHZhWEJXVDFsM1MwdDZkVlY1YTNGRlEzUnFiR2hLTkVGclYyRkVVeXRhZUV0RmNVOWhaVGwwYmtOblpVaHNiRnBGTDA5U1oyVk5ZWGd5V0U1RGIwZzJjM0pVUlZKamEzTnFlbHBhY2tGWGVFdHpaR1oyVm5KWVRucERVamxFZUZaQlUzVkpOa3g2ZDJnNFJGTnNNa1ZQYjJ0aWMyRnVXaXNyTDBweFRXVkJRa1ptVUhkcWVYZHlZakJ3Y2tWVmVUQndZV1ZXYzNWa0t6QndaV1Y0U3k4MUswVTJhM0JaUjBzMFdrc3libXR2Vmt4MVowVTFkR0ZJY2tGcU9ETlJLMUJQWW1KMlQzcFhZMFpyY0c1V1MzbHFielpMVVVGdFdEWlhTa0ZuVFVKQlFVZHFaMmRHUjAxSlNVSlJha0ZVUW1kT1ZraFRWVVZFUkVGTFFtZG5ja0puUlVaQ1VXTkVRVlJCWkVKblRsWklVa1ZGUm1wQlZXZG9TbWhrU0ZKc1l6TlJkVmxYTld0amJUbHdXa00xYW1JeU1IZGhRVmxKUzNkWlFrSlJWVWhCVVVWRldFUkNZVTFETUVkRFEzTkhRVkZWUmtKNlFVTm9hVVp2WkVoU2QwOXBPSFpqUjNSd1RHMWtkbUl5WTNaYU0wNTVUV2s1U0ZaR1RraFRWVVpJVFhrMWFtTnVVWGRMVVZsSlMzZFpRa0pSVlVoTlFVZEhTRmRvTUdSSVFUWk1lVGwyV1ROT2QweHVRbkpoVXpWdVlqSTVia3d3WkZWVk1HUktVVlZqZWsxQ01FZEJNVlZrUkdkUlYwSkNVVWM0U1hKUmRFWlNOa05WVTJ0cGEySXpZV2x0YzIweU5tTkNWRUZOUW1kT1ZraFNUVUpCWmpoRlFXcEJRVTFDT0VkQk1WVmtTWGRSV1UxQ1lVRkdTR1pEZFVaRFlWb3pXakp6VXpORGFIUkRSRzlJTm0xbWNuQk1UVU5GUjBFeFZXUkpRVkZoVFVKbmQwUkJXVXRMZDFsQ1FrRklWMlZSU1VaQmVrRkpRbWRhYm1kUmQwSkJaMGwzVFZGWlJGWlNNR1pDUTI5M1MwUkJiVzlEVTJkSmIxbG5ZVWhTTUdORWIzWk1NazU1WWtNMWQyRXlhM1ZhTWpsMlduazVTRlpHVGtoVFZVWklUWGsxYW1OdGQzZEVVVmxLUzI5YVNXaDJZMDVCVVVWTVFsRkJSR2RuUlVKQlJpOVNlazV1UXpWRWVrSlZRblJ1YURKdWRFcE1WMFZSYURsNlJXVkdXbVpRVERsUmIydHliRUZ2V0dkcVYyZE9PSEJUVWxVeGJGWkhTWEIwZWsxNFIyaDVNeTlQVWxKYVZHRTJSREpFZVRob2RrTkVja1pKTXl0c1Exa3dNVTFNTlZFMldFNUZOVkp6TW1ReFVtbGFjRTF6ZWtRMFMxRmFUa2N6YUZvd1FrWk9VUzlqYW5KRGJVeENUMGRMYTBWVk1XUnRRVmh6UmtwWVNtbFBjakpEVGxSQ1QxUjFPVVZpVEZkb1VXWmtRMFl4WW5kNmVYVXJWelppVVZOMk9GRkVialZQWkUxVEwxQnhSVEZrUldkbGRDODJSVWxTUWpjMk1VdG1XbEVyTDBSRk5reHdNMVJ5V2xSd1QwWkVSR2RZYUN0TVowZFBjM2RvUld4cU9XTXpkbHBJUjBwdWFHcHdkRGh5YTJKcGNpOHlkVXhIWm5oc1ZsbzBTekY0TlVSU1RqQlFWVXhrT1hsUVUyMXFaeXRoYWpFcmRFaDNTVEZ0VVcxYVZsazNjWFpQTlVSbmFFOTRhRXBOUjJ4Nk5teE1hVnB0ZW05blBTSXNJazFKU1VWWVJFTkRRVEJUWjBGM1NVSkJaMGxPUVdWUGNFMUNlamhqWjFrMFVEVndWRWhVUVU1Q1oydHhhR3RwUnpsM01FSkJVWE5HUVVSQ1RVMVRRWGRJWjFsRVZsRlJURVY0WkVoaVJ6bHBXVmQ0VkdGWFpIVkpSa3AyWWpOUloxRXdSV2RNVTBKVFRXcEZWRTFDUlVkQk1WVkZRMmhOUzFJeWVIWlpiVVp6VlRKc2JtSnFSVlJOUWtWSFFURlZSVUY0VFV0U01uaDJXVzFHYzFVeWJHNWlha0ZsUm5jd2VFNTZRVEpOVkZWM1RVUkJkMDVFU21GR2R6QjVUVlJGZVUxVVZYZE5SRUYzVGtSS1lVMUdVWGhEZWtGS1FtZE9Wa0pCV1ZSQmJGWlVUVkkwZDBoQldVUldVVkZMUlhoV1NHSXlPVzVpUjFWblZraEtNV016VVdkVk1sWjVaRzFzYWxwWVRYaEtWRUZxUW1kT1ZrSkJUVlJJUldSMllqSmtjMXBUUWtwaWJsSnNZMjAxYkdSRFFrSmtXRkp2WWpOS2NHUklhMmRTZWsxM1oyZEZhVTFCTUVkRFUzRkhVMGxpTTBSUlJVSkJVVlZCUVRSSlFrUjNRWGRuWjBWTFFXOUpRa0ZSUkV0VmEzWnhTSFl2VDBwSGRXOHlia2xaWVU1V1YxaFJOVWxYYVRBeFExaGFZWG8yVkVsSVRFZHdMMnhQU2lzMk1EQXZOR2hpYmpkMmJqWkJRVUl6UkZaNlpGRlBkSE0zUnpWd1NEQnlTbTV1VDBaVlFVczNNVWMwYm5wTFRXWklRMGRWYTNOWEwyMXZibUVyV1RKbGJVcFJNazRyWVdsamQwcExaWFJRUzFKVFNXZEJkVkJQUWpaQllXaG9PRWhpTWxoUE0yZzVVbFZyTWxRd1NFNXZkVUl5Vm5wNGIwMVliR3Q1VnpkWVZWSTFiWGMyU210TVNHNUJOVEpZUkZadlVsUlhhMDUwZVRWdlEwbE9USFpIYlc1U2Mwb3hlbTkxUVhGWlIxWlJUV012TjNONUt5OUZXV2hCVEhKV1NrVkJPRXRpZEhsWUszSTRjMjUzVlRWRE1XaFZjbmRoVnpaTlYwOUJVbUU0Y1VKd1RsRmpWMVJyWVVsbGIxbDJlUzl6UjBsS1JXMXFVakIyUmtWM1NHUndNV05UWVZkSmNqWXZOR2MzTW00M1QzRllkMlpwYm5VM1dsbFhPVGRGWm05UFUxRktaVUY2UVdkTlFrRkJSMnBuWjBWNlRVbEpRa3g2UVU5Q1owNVdTRkU0UWtGbU9FVkNRVTFEUVZsWmQwaFJXVVJXVWpCc1FrSlpkMFpCV1VsTGQxbENRbEZWU0VGM1JVZERRM05IUVZGVlJrSjNUVU5OUWtsSFFURlZaRVYzUlVJdmQxRkpUVUZaUWtGbU9FTkJVVUYzU0ZGWlJGWlNNRTlDUWxsRlJraG1RM1ZHUTJGYU0xb3ljMU16UTJoMFEwUnZTRFp0Wm5Kd1RFMUNPRWRCTVZWa1NYZFJXVTFDWVVGR1NuWnBRakZrYmtoQ04wRmhaMkpsVjJKVFlVeGtMMk5IV1ZsMVRVUlZSME5EYzBkQlVWVkdRbmRGUWtKRGEzZEtla0ZzUW1kbmNrSm5SVVpDVVdOM1FWbFpXbUZJVWpCalJHOTJUREk1YW1NelFYVmpSM1J3VEcxa2RtSXlZM1phTTA1NVRXcEJlVUpuVGxaSVVqaEZTM3BCY0UxRFpXZEtZVUZxYUdsR2IyUklVbmRQYVRoMldUTktjMHh1UW5KaFV6VnVZakk1Ymt3eVpIcGpha2wyV2pOT2VVMXBOV3BqYlhkM1VIZFpSRlpTTUdkQ1JHZDNUbXBCTUVKbldtNW5VWGRDUVdkSmQwdHFRVzlDWjJkeVFtZEZSa0pSWTBOQlVsbGpZVWhTTUdOSVRUWk1lVGwzWVRKcmRWb3lPWFphZVRsNVdsaENkbU15YkRCaU0wbzFUSHBCVGtKbmEzRm9hMmxIT1hjd1FrRlJjMFpCUVU5RFFWRkZRVWhNWlVwc2RWSlVOMkoyY3pJMlozbEJXamh6YnpneGRISlZTVk5rTjA4ME5YTnJSRlZ0UVdkbE1XTnVlR2hITVZBeVkwNXRVM2hpVjNOdmFVTjBNbVYxZURsTVUwUXJVRUZxTWt4SldWSkdTRmN6TVM4MmVHOXBZekZyTkhSaVYxaHJSRU5xYVhJek4zaFVWRTV4VWtGTlVGVjVSbEpYVTJSMmRDdHViRkJ4ZDI1aU9FOWhNa2t2YldGVFNuVnJZM2hFYWs1VFpuQkVhQzlDWkRGc1drNW5aR1F2T0dOTVpITkZNeXQzZVhCMVprbzVkVmhQTVdsUmNHNW9PWHBpZFVaSmQzTkpUMDVIYkRGd00wRTRRMmQ0YTNGSkwxVkJhV2d6U21GSFQzRmpjR05rWVVOSmVtdENZVkk1ZFZsUk1WZzBhekpXWnpWQlVGSk1iM1Y2Vm5rM1lUaEpWbXMyZDNWNU5uQnRLMVEzU0ZRMFRGazRhV0pUTlVaRldteG1RVVpNVTFjNFRuZHpWbm81VTBKTE1sWnhiakZPTUZCSlRXNDFlRUUyVGxwV1l6ZHZPRE0xUkV4QlJuTm9SVmRtUXpkVVNXVXpaejA5SWwxOS5leUp1YjI1alpTSTZJbXhYYTBscWVEZFBOSGxOY0ZaQlRtUjJVa1JZZVhWUFVrMUdiMjVWWWxaYWRUUXZXSGszU1hCMlpGSkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVkZMWjJ4NFNIbG1ibEpMUVZwV2NXbEtaRWx4ZEhGbU5FazVaSGd3YjA4MkwzcEJUemhVYmtSdmFuWkZXa0Z4TWtSYWEwSjVTVEZtWTI5WFZsRkZjUzlQTTBaTVNEVmhUM2Q2WW5KeWVISktOalZWTldSWmNXeEJVVWxFU21sQlFrbFdaMmRvTlU5S1psbFNSSHBXUjBsdmQwdHhWVFUzUVc1dlZtcHFaRzF0YWtkcE9YcHNUV3RxUVZaV09VUkJhVmREUkhJd2FWTnBNSFpwU1V0T1VFMVVTV1JPTWpoblYwNXRhMk4zVDNJMlJGRjROalpOVUdabU0wOWtiU3QxTm1WS2NVeENiREZJTWxNeWRISkJRa2hNYVc1cmJuTjVWazFRYlM5Q1RsVldXakpLUm14eU9EQWlMQ0owYVcxbGMzUmhiWEJOY3lJNk1UVXlPRGt4TVRZek5ETTROU3dpWVhCclVHRmphMkZuWlU1aGJXVWlPaUpqYjIwdVoyOXZaMnhsTG1GdVpISnZhV1F1WjIxeklpd2lZWEJyUkdsblpYTjBVMmhoTWpVMklqb2lTazlETTFWcmMyeHpkVlo2TVRObFQzQnVSa2s1UW5CTWIzRkNaemxyTVVZMlQyWmhVSFJDTDBkcVRUMGlMQ0pqZEhOUWNtOW1hV3hsVFdGMFkyZ2lPbVpoYkhObExDSmhjR3REWlhKMGFXWnBZMkYwWlVScFoyVnpkRk5vWVRJMU5pSTZXeUpIV0ZkNU9GaEdNM1pKYld3ekwwMW1ibTFUYlhsMVMwSndWRE5DTUdSWFlraFNVaTgwWTJkeEsyZEJQU0pkTENKaVlYTnBZMGx1ZEdWbmNtbDBlU0k2Wm1Gc2MyVXNJbUZrZG1salpTSTZJbEpGVTFSUFVrVmZWRTlmUmtGRFZFOVNXVjlTVDAwc1RFOURTMTlDVDA5VVRFOUJSRVZTSW4wLmlDRjZEMm9zOERZdURWT250M3pESkIybVNYblpqdFdKdGxfanpTRHg1TXJSQzlBMmZtRkJaNno1a3BRWjJNaVE3b290ajlXa0hNZ3hxSWhyWDNkbGgyUE9IQXdrSVMzNHlTakxWTnNTUHByRTg0ZVpncVNGTE1FWVQwR1IyZVZMSEFNUE44bjVSOEs2YnVET0dGM25TaTZHS3pHNTdabGw4Q1NvYjJ5aUFTOXI3c3BkQTZIMFRESC1OR3pTZGJNSUlkOGZaRDFkekZLTlFyNzdiNmxiSUFGZ1FiUlpCcm5wLWUtSDRpSDZkMjFvTjJOQVlSblI1WVVSYWNQNmtHR2oyY0Z4c3dFMjkwOHd4djloaVlOS05vamVldThYYzRJdDdQYmhsQXVPN3l3aFFGQTgxaVBDQ0ZtMTFCOGNmVVhiV0E4bF8ydHROUEJFTUdNNi1aNlZ5UQ"
    }
});
*/

module.exports = router;
