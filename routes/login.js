var express = require('express');
var passport = require('passport');
var router = express.Router();

router.get('/login',
  function(req, res, next){
    res.render('login');
  });
  
router.post('/challenge', function(req, res, next) {
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

module.exports = router;
