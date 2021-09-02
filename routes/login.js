var express = require('express');
var passport = require('passport');
var base64url = require('base64url');
var router = express.Router();

router.get('/login',
  function(req, res, next){
    res.render('login');
  });

router.post('/login/public-key',
  function(req, res, next) {
    console.log('RESPONSE!');
    console.log(req.headers);
    console.log(req.body);
    
    // https://www.w3.org/TR/webauthn/#registering-a-new-credential
    
    //var response = req.body.response;
    //var clientData = JSON.parse(base64url.decode(response.clientDataJSON));
    //console.log(clientData);
    
    next();
  },
  passport.authenticate('webauthn', { failureRedirect: '/login' }),
  function(req, res, next) {
    console.log('AUTHENTICATED!');
    //res.redirect('/');
    res.json({ ok: true });
  });

module.exports = router;
