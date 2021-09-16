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


window.onload = function() {
  document.getElementById('login').addEventListener('click', function(e) {
    
    
    console.log('login...');
    e.preventDefault();
    //return;
    
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
    
      if (this.readyState === XMLHttpRequest.DONE) {
        console.log(this.responseText)
        
        
        var json = JSON.parse(this.responseText);
        
        var enc = new TextEncoder(); // always utf-8
        json.challenge = enc.encode(json.challenge); // encode to ArrayBuffer
        if (json.allowCredentials) {
        //json.allowCredentials[0].id = enc.encode(json.allowCredentials[0].id); // encode to ArrayBuffer
        //json.allowCredentials[0].id = base64url.decode(json.allowCredentials[0].id);
        
          var i = 0, len = json.allowCredentials.length;
          for (i = 0; i < len; ++i) {
            json.allowCredentials[i].id = base64url.decode(json.allowCredentials[i].id);
          }
        
        }
      
        console.log(json);
        //return;
        
        navigator.credentials.get({ publicKey: json })
          .then(function(response) {
            console.log(response)
            //return;
          
            var xhr = new XMLHttpRequest();
            xhr.open('POST', '/login/public-key', true);
            xhr.onreadystatechange = function() {
              console.log(this.readyState);
              console.log(this.status);
              console.log(this.responseText)
              
              if (this.readyState === XMLHttpRequest.DONE) {
                window.location = '/';
              }
            };
            
            xhr.setRequestHeader('Content-Type', 'application/json');
            xhr.send(JSON.stringify(publicKeyCredentialToJSON(response)));
          })
          .catch(function(err) {
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
};
