var express = require('express');
var path = require('path');
var passport = require('passport');
var Strategy = require('passport-webauthentication').Strategy;


passport.use(new Strategy(
  function verify(id, cb) {
    console.log('WEB AUTHN VERIFY');
    console.log(id);
    
    var pk = "-----BEGIN PUBLIC KEY-----\n" + 
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYk0IJlg+EpjWmsSkV0K3/KdeJRI6\n' + 
'2ABcPAflwTwqXXzTLDj9Sq6PR0pZR3n1ydJHIFSbozFTfLGbl44naii6LQ==\n' +
'-----END PUBLIC KEY-----\n'
    
    
    return cb(null, { name: 'John Doe'}, pk)
    
  })
);


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
