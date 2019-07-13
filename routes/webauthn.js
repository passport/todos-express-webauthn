var express = require('express');
var passport = require('passport');
var base64url = require('base64url');
var router = express.Router();

router.post('/request', function(req, res, next) {
  console.log('CHALLENGE!');
  console.log(req.headers);
  console.log(req.body);
  
  // TODO: Look up authenticators by username/id
  
  var opts = {
    challenge: '5678', // TODO: Make this random,
    
    allowCredentials: [ {
      type: 'public-key',
      id: 'p5XN9H3kPWVymj0GcGDZtElg2Y2g4AISMWyUjjz3HEZBeHjamcknUsyTDy15zEGRXJCsyFVAEQ8Aq8_PbdkZnw',
      //id: '123',
      transports: ['usb', 'nfc', 'ble']
    } ]
  };
  
  res.json(opts);
});

router.post('/response',
  function(req, res, next) {
    console.log('RESPONSE!');
    console.log(req.headers);
    console.log(req.body);
    
    var response = req.body.response;
    var clientData = JSON.parse(base64url.decode(response.clientDataJSON));
    console.log(clientData);
    
    next();
  },
  passport.authenticate('webauthn', { failureRedirect: '/login' }));

module.exports = router;
