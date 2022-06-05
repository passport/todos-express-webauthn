function _arrayBufferToBase64( buffer ) {
    var binary = '';
    var bytes = new Uint8Array( buffer );
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
        binary += String.fromCharCode( bytes[ i ] );
    }
    return window.btoa( binary );
}

function publicKeyCredentialToJSON(cred) {
  if (cred instanceof Array) {
      var arr = [];
      for(var i of cred)
          arr.push(publicKeyCredentialToJSON(i));

      return arr
  }

  if (cred instanceof ArrayBuffer) {
    return base64url.encode(cred)
      //return _arrayBufferToBase64(cred)
  }

  if (cred instanceof Object) {
      let obj = {};

      for (var key in cred) {
          obj[key] = publicKeyCredentialToJSON(cred[key])
      }
      
      if (cred.getTransports) {
        obj.transports = cred.getTransports();
      }
      
      if (cred.getClientExtensionResults) {
        obj.clientExtensionResults = cred.getClientExtensionResults();
      }

      return obj
  }

  return cred
}


// https://stackoverflow.com/questions/7542586/new-formdata-application-x-www-form-urlencoded
function urlencodedFormData(data){
  var s = '';
  function encode(s) { return encodeURIComponent(s).replace(/%20/g,'+'); }
  for (var pair of data.entries()) {
    if (typeof pair[1]=='string') {
      s += (s ? '&' : '') + encode(pair[0]) + '=' + encode(pair[1]);
    }
  }
  return s;
}


window.addEventListener('load', function() {
  
  document.querySelector('form').addEventListener('submit', function(event) {
    if (!window.PublicKeyCredential) { return; }
    
    event.preventDefault();
    
    return fetch('/signup/public-key/challenge', {
      method: 'POST',
      headers: {
        'Accept': 'application/json'
      },
      body: new FormData(event.target),
    })
    .then(function(response) {
      return response.json();
    })
    .then(function(json) {
      // https://chromium.googlesource.com/chromium/src/+/master/content/browser/webauth/uv_preferred.md
      return navigator.credentials.create({
        publicKey: {
          rp: {
            name: 'Todos'
          },
          user: {
            id: base64url.decode(json.user.id),
            name: json.user.name,
            displayName: json.user.displayName
          },
          challenge: base64url.decode(json.challenge),
          pubKeyCredParams: [
            {
              type: 'public-key',
              alg: -7 // "ES256" IANA COSE Algorithms registry
            }
          ],
          //attestation: 'none',
          authenticatorSelection: {
            userVerification: 'discouraged',
            //authenticatorAttachment: "platform",
            residentKey: 'required'
          },
          //extensions: {
          //  credProps: true
          //}
        }
      });
    })
    .then(function(credential) {
      console.log(credential);
      
      return fetch('/login/public-key', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify(publicKeyCredentialToJSON(credential))
      });
    })
    .then(function(response) {
      return response.json();
    })
    .then(function(json) {
      window.location.href = json.location;
    })
    .catch(function(error) {
      console.log(error);
    });
  });
  
});
