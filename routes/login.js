var express = require('express');
var passport = require('passport');
var base64url = require('base64url');
var db = require('../db');

var router = express.Router();

router.get('/login',
  function(req, res, next){
    res.render('login');
  });

router.post('/login',
  function(req, res, next){
    console.log('LOGIN');
    console.log(req.headers);
    console.log(req.body)
    
    function challenge(keys) {
      res.format({
        'application/json': function () {
          var options = {
            challenge: '5678', // TODO: Make this random,
          };
          
          if (keys) {
            options.allowCredentials = [];
            
            keys.forEach(function(row, i) {
              var key = {
                type: 'public-key',
                id: row.external_id
                // TODO: put transports in
                //transports: ['usb', 'nfc', 'ble']
                //transports: ['internal']
              };
        
              options.allowCredentials.push(key);
            });
          }
          
          console.log(options)
          
          res.send(options);
        },

        default: function () {
          // TODO
        }
      });
    }
    
    
    var username = req.body.username;
    if (!username) {
      // challenge for client-side discoverable keys (aka resident keys)
      challenge();
    } else {
      console.log('TODO: lookupu username');
      
      db.get('SELECT rowid AS id FROM users WHERE username = ?', [ username ], function(err, row) {
        if (err) { return cb(err); }
        
        // TODO: Handle undefined row
        //if (!row) { return cb(null, false, { message: 'Incorrect username or password.' }); }
        
        console.log('FOUND USER');
        console.log(row);
        
        db.all('SELECT rowid as id, * FROM public_key_credentials WHERE user_id = ?', [ row.id ], function(err, rows) {
          if (err) { return next(err); }
          
          console.log('GOT KEYS');
          console.log(rows);
          
          challenge(rows);
        });
      });
    }
    
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
  
router.post('/login/public-key/2',
  // TODO: 403 if not logged in
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
  passport.authenticate('webauthn-2f', { failureRedirect: '/login' }),
  function(req, res, next) {
    console.log('AUTHENTICATED!');
    //res.redirect('/');
    res.json({ ok: true });
  });

module.exports = router;
