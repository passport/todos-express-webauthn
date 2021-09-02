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

      return obj
  }

  return cred
}


window.onload = function() {
  
  document.getElementById('register').addEventListener('click', function(e) {
    console.log('sign up...');
    e.preventDefault();
    //return;
    
    
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/webauthn/create', true);
    xhr.onreadystatechange = function() {
      
      if (this.readyState === XMLHttpRequest.DONE) {
        console.log(this.responseText)
        //return;
        
        var json = JSON.parse(this.responseText);
        
        var userID = json.user.id;
        
        var enc = new TextEncoder(); // always utf-8
        json.challenge = enc.encode(json.challenge); // encode to ArrayBuffer
        json.user.id = enc.encode(json.user.id); // encode to ArrayBuffer
        
        navigator.credentials.create({ publicKey: json })
          .then(function(response) {
            console.log(response);
            
            var xhr = new XMLHttpRequest();
            xhr.open('POST', '/login/public-key', true);
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
    
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.send(JSON.stringify({
      foo: 'bar',
      username: document.getElementById('username').value,
      name: document.getElementById('name').value
    }));
    
    e.preventDefault();
  });
};
