var express = require('express');
var path = require('path');
var passport = require('passport');
var Strategy = require('passport-webauthentication').Strategy;
var db = require('./db')


passport.use(new Strategy(
  function verify(id, cb) {
    console.log('WEB AUTHN VERIFY');
    console.log(id);
    
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
  })
);

passport.serializeUser(function(user, cb) {
  cb(null, user.id);
});

passport.deserializeUser(function(id, cb) {
  db.get(id, function(err, doc) {
    // TODO: handle 'not_found' error
    if (err) { return cb(err); }
    
    var user = {
      id: doc._id,
      username: doc.username,
      displayName: doc.displayName
    }
    return cb(null, user);
  });
  
  
  /*
  db.users.findById(id, function (err, user) {
    if (err) { return cb(err); }
    cb(null, user);
  });
  */
});


var indexRouter = require('./routes/index');
var loginRouter = require('./routes/login');
var webauthnRouter = require('./routes/webauthn');
var accountRouter = require('./routes/account');

// Create a new Express application.
var app = express();

// Configure view engine to render EJS templates.
app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');

// Use application-level middleware for common functionality, including
// logging, parsing, and session handling.
app.use(require('morgan')('combined'));
app.use(require('body-parser').json());
app.use(require('express-session')({ secret: 'keyboard cat', resave: false, saveUninitialized: false }));
app.use(express.static(path.join(__dirname, 'public')));

// Initialize Passport and restore authentication state, if any, from the
// session.
app.use(passport.initialize());
app.use(passport.session());

app.use('/', indexRouter);
app.use('/', loginRouter);
app.use('/webauthn', webauthnRouter);
app.use('/account', accountRouter);

app.listen(3000);
