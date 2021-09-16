var passport = require('passport');
var Strategy = require('passport-webauthentication').Strategy;
var MFAStrategy = require('passport-webauthentication').MFAStrategy;
var db = require('../db');


module.exports = function() {
  
  
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
      cb(null, { id: user.id, username: user.username });
    });
  });

  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });
  
};
