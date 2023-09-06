window.addEventListener('load', function() {
  
  document.getElementById('siw-public-key').addEventListener('click', function(event) {
    if (!window.PublicKeyCredential) {
      alert('Passkeys are not supported by this browser');
      return;
    }
    
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
          challenge: base64url.decode(json.challenge)
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
  
  if (window.PublicKeyCredential && PublicKeyCredential.isConditionalMediationAvailable) {
    PublicKeyCredential.isConditionalMediationAvailable()
    .then(function(available) {
      if (!available) { return; }
      
      document.getElementById('siw-public-key').remove();
      
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
          mediation: 'conditional',
          publicKey: {
            challenge: base64url.decode(json.challenge)
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
      });
    })
    .catch(function(error) {
      console.log(error);
    });
  }
  
});
