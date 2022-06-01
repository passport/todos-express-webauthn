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
  console.log('load...');
  console.log(PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable)
  console.log(PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable())
  
  PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
  .then(function(x) {
    console.log(x)
  })
  
  
  document.getElementById('siw-public-key').addEventListener('click', function(event) {
    if (!window.PublicKeyCredential) { return; }
    
    event.preventDefault();
    
    var encoder = new TextEncoder();
    
    navigator.credentials.get({
      publicKey: {
        challenge: encoder.encode('1234'),
        //allowCredentials: [
        //  { type: 'public-key', id: base64url.decode('VjXl8fuJXIAqLg-BVrR5oeLLfee6gBGKXdMxo6xtMySugJfU2HNvTJk84T1DgFYtJDpDrwL2Bg_QM4xQwVAutA') },
        //  { type: 'public-key', id: base64url.decode('noMuGuaaVLubAVjuS6Z2BYrrBpajYhtjnFgvSjk0IV1LJeVrupbpnw') }
        //]
      }
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
