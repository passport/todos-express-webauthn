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
      var body = {
        response: {
          clientDataJSON: base64url.encode(credential.response.clientDataJSON),
          attestationObject: base64url.encode(credential.response.attestationObject)
        }
      };
      if (credential.response.getTransports) {
        body.response.transports = credential.response.getTransports();
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
