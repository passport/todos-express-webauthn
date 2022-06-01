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
    
    return fetch('/signup/public-key', {
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
      var encoder = new TextEncoder();
      
      return navigator.credentials.create({
        publicKey: {
          rp: {
            name: 'Todos'
          },
          user: {
            id: encoder.encode(json.user.id),
            name: json.user.username,
            displayName: json.user.name
          },
          challenge: encoder.encode(json.challenge),
          pubKeyCredParams: [
            {
              type: 'public-key',
              alg: -7 // "ES256" IANA COSE Algorithms registry
            }
          ],
          authenticatorSelection: {
            //authenticatorAttachment: "platform",
            residentKey: 'required'
          },
        }
      });
    })
    .then(function(credential) {
      console.log('created!');
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
    
    
    return;
  
  
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
    
      if (this.readyState === XMLHttpRequest.DONE) {
        console.log(this.responseText)
        //return;
      
        var json = JSON.parse(this.responseText);
      
        var userID = json.user.id;
      
        var enc = new TextEncoder(); // always utf-8
        json.challenge = enc.encode(json.challenge); // encode to ArrayBuffer
        json.user.id = enc.encode(json.user.id); // encode to ArrayBuffer
      
        console.log('CREATE WITH');
        console.log(json)
      
        navigator.credentials.create({ publicKey: json })
          .then(function(response) {
            console.log(response);
          
            var xhr = new XMLHttpRequest();
            xhr.open('POST', '/login/public-key/2', true);
            xhr.onreadystatechange = function() {
              console.log('REGISTER READY STATE CHANGE!')
              console.log(this.readyState);
              console.log(this.status);
              console.log(this.responseText)
            };
          
            xhr.setRequestHeader('Content-Type', 'application/json');
            // TODO: Remove this in favor of session
            //xhr.setRequestHeader('X-User-ID', userID);
            xhr.send(JSON.stringify(publicKeyCredentialToJSON(response)));
          })
          .catch(function(err) {
            console.log('ERROR');
            console.log(err);
            console.log(err.code);
            console.log(err.message);
          });
      }
    };
  
    var formEl = document.querySelector('form');
    var formData = new FormData(formEl);
    xhr.open('POST', formEl.action, true);
    xhr.setRequestHeader('Content-Type','application/x-www-form-urlencoded');
    xhr.setRequestHeader('Accept', 'application/json');
    xhr.send(urlencodedFormData(formData));
  });
  
});
