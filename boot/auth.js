var passport = require('passport');
var Strategy = require('passport-webauthentication').Strategy;
var db = require('../db');


module.exports = function() {
  
  
  passport.use(new Strategy(
    function verify(id, cb) {
      console.log('WEB AUTHN VERIFY');
      console.log(id);
    
      /*
      var query = {
        selector: { externalID: id }
      };
    
      console.log(query);
    
      db.find(query, function(err, result) {
        console.log(err);
        console.log(result);
    
        if (err) { return cb(err); }
        var doc = result.docs[0];
    
        db.get(doc.userID, function(err, result) {
          console.log('GOT USER ID!');
          console.log(err);
          console.log(result);
        
          var user = {
            id: result._id,
            username: result.username,
            displayName: result.displayName
          }
          return cb(null, user, doc.publicKey);
        
        });
    
    
        //return cb(null, { name: 'John Doe'}, doc.publicKey);
      });
      */
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
