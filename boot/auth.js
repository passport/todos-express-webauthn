var passport = require('passport');
var Strategy = require('passport-webauthentication').Strategy;
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
        
        return cb(null, { name: 'John Doe'}, row.public_key);
        
      });
    }, function register(id, publicKey, cb) {
      console.log('REGISTER WEBAUTHN!');
      console.log(id);
      console.log(publicKey)
      
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
  
}
