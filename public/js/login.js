window.addEventListener('load', function() {
  
  document.getElementById('siw-public-key').addEventListener('click', function(event) {
    if (!window.PublicKeyCredential) { return; }
    
    event.preventDefault();
    
    return fetch('/login/public-key/challenge', {
      method: 'POST',
      headers: {
        'Accept': 'application/json'
      }
    })
    .then(function(response) {
      return response.json();
    })
    .then(function(json) {
      return navigator.credentials.get({
        publicKey: {
          challenge: base64url.decode(json.challenge),
          //allowCredentials: [
          //  { type: 'public-key', id: base64url.decode('VjXl8fuJXIAqLg-BVrR5oeLLfee6gBGKXdMxo6xtMySugJfU2HNvTJk84T1DgFYtJDpDrwL2Bg_QM4xQwVAutA') },
          //  { type: 'public-key', id: base64url.decode('noMuGuaaVLubAVjuS6Z2BYrrBpajYhtjnFgvSjk0IV1LJeVrupbpnw') }
          //]
        }
      });
    })
    .then(function(credential) {
      var body = {
        id: credential.id,
        response: {
          clientDataJSON: base64url.encode(credential.response.clientDataJSON),
          authenticatorData: base64url.encode(credential.response.authenticatorData),
          signature: base64url.encode(credential.response.signature),
          userHandle: credential.response.userHandle ? base64url.encode(credential.response.userHandle) : null
        }
      };
      if (credential.authenticatorAttachment) {
        body.authenticatorAttachment = credential.authenticatorAttachment;
      }
      
      return fetch('/login/public-key', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify(body)
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
