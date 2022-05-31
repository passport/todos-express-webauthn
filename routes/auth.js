var express = require('express');
var passport = require('passport');
var Strategy = require('passport-webauthentication').Strategy;
var MFAStrategy = require('passport-webauthentication').MFAStrategy;
var base64url = require('base64url');
var db = require('../db');


passport.use(new Strategy(
  function verify(id, cb) {
    console.log('WEB AUTHN VERIFY');
    console.log(id);
    
    db.get('SELECT rowid AS id, * FROM public_key_credentials WHERE external_id = ?', [ id ], function(err, row) {
      if (err) { return cb(err); }
      if (!row) { return cb(null, false); }
      
      console.log(row);
      
      // TODO: Implement a separate callback to look up the user
      
      
      var publicKey = row.public_key;
      
      db.get('SELECT rowid AS id, username, name FROM users WHERE rowid = ?', [ row.user_id ], function(err, row) {
        if (err) { return next(err); }

        // TODO: Handle undefined row.
        var user = {
          id: row.id.toString(),
          username: row.username,
          displayName: row.name
        };
        return cb(null, user, publicKey);
      });
    });
  }, function register(id, publicKey, cb) {
    console.log('REGISTER WEBAUTHN!');
    console.log(id);
    console.log(publicKey)
    //return;
    
    db.run('INSERT INTO public_key_credentials (external_id, public_key) VALUES (?, ?)', [
      id,
      publicKey
    ], function(err) {
      console.log(err);
      
      if (err) { return next(err); }
    
        
      // TODO: Return true
    });
    
  })
);

passport.use(new MFAStrategy(
  function verify(id, cb) {
    console.log('WEB AUTHN VERIFY');
    console.log(id);
    
    db.get('SELECT rowid AS id, * FROM public_key_credentials WHERE external_id = ?', [ id ], function(err, row) {
      if (err) { return cb(err); }
      if (!row) { return cb(null, false); }
      
      console.log(row);
      
      // TODO: Implement a separate callback to look up the user
      
      return cb(null, { name: 'John Doe'}, row.public_key);
      
    });
  }, function register(user, id, publicKey, cb) {
    console.log('MFA REGISTER WEBAUTHN!');
    console.log(user);
    console.log(id);
    console.log(publicKey)
    //return;
    
    db.run('INSERT INTO public_key_credentials (external_id, public_key, user_id) VALUES (?, ?, ?)', [
      id,
      publicKey,
      user.id
    ], function(err) {
      console.log(err);
      
      if (err) { return cb(err); }
      return cb(null, true);
    });
    
  })
);


passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    cb(null, { id: user.id, username: user.username, displayName: user.displayName });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});


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

router.post('/logout', function(req, res, next) {
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/');
  });
});

router.get('/signup', function(req, res, next) {
  res.render('signup');
});

router.post('/signup/public-key', function(req, res, next) {
  console.log('sign up!');
  console.log(req.body);
  
  
  
  
  return;
  
  var salt = crypto.randomBytes(16);
  crypto.pbkdf2(req.body.password, salt, 310000, 32, 'sha256', function(err, hashedPassword) {
    if (err) { return next(err); }
    db.run('INSERT INTO users (username, hashed_password, salt) VALUES (?, ?, ?)', [
      req.body.username,
      hashedPassword,
      salt
    ], function(err) {
      if (err) { return next(err); }
      var user = {
        id: this.lastID,
        username: req.body.username
      };
      req.login(user, function(err) {
        if (err) { return next(err); }
        res.redirect('/');
      });
    });
  });
});

module.exports = router;
