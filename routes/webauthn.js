var express = require('express');
var passport = require('passport');
var cose2jwk = require('cose-to-jwk');
var jwk2pem = require('jwk-to-pem');
var cbor = require('cbor');
var base64url = require('base64url');
var db = require('../db');
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
      //id: 'p5XN9H3kPWVymj0GcGDZtElg2Y2g4AISMWyUjjz3HEZBeHjamcknUsyTDy15zEGRXJCsyFVAEQ8Aq8_PbdkZnw',
      //id: 'jWcLBKE7CnLmJTecFZNTSFnWyaokRzpu3cg-b1qMBweUpCHMPhZ9MVL4oVFI3Vb4_K-d4wJoxfjjZ4uU17xNQA',
      id: 'Vj1ZA6yKxblqKMhVduxJdOUt9tdz6333z7vygjM6qj8ZMc07m3tyGHwGYRDBOPl1PGRqHxdRQraYbaTjC7p0NQ',
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
    
    // https://www.w3.org/TR/webauthn/#registering-a-new-credential
    
    var response = req.body.response;
    var clientData = JSON.parse(base64url.decode(response.clientDataJSON));
    console.log(clientData);
    
    next();
  },
  passport.authenticate('webauthn', { failureRedirect: '/login' }));

module.exports = router;
