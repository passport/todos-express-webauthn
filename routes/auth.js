var express = require('express');
var passport = require('passport');
var WebAuthnStrategy = require('passport-webauthentication');
var base64url = require('base64url');
var db = require('../db');


passport.use(new WebAuthnStrategy(function verify(id, cb) {
  db.get('SELECT * FROM public_key_credentials WHERE external_id = ?', [ id ], function(err, row) {
    if (err) { return cb(err); }
    if (!row) { return cb(null, false); }
    var publicKey = row.public_key;
    db.get('SELECT * FROM users WHERE rowid = ?', [ row.user_id ], function(err, row) {
      if (err) { return cb(err); }
      if (!row) { return cb(null, false); }
      return cb(null, row, publicKey);
    });
  });
}, function register(id, publicKey, cb) {
  // FIXME: Make user an argument to this function
  var user = {
    id: 1,
    username: 'alice'
  };
  
  db.run('INSERT INTO public_key_credentials (user_id, external_id, public_key) VALUES (?, ?, ?)', [
    user.id,
    id,
    publicKey
  ], function(err) {
    if (err) { return cb(err); }
    return cb(null, user);
  });
}));

passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    cb(null, { id: user.id, username: user.username, name: user.name });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});


var router = express.Router();

router.get('/login', function(req, res, next) {
  res.render('login');
});

router.post('/login/public-key', passport.authenticate('webauthn', {
  failureMessage: true,
  failWithError: true
}), function(req, res, next) {
  res.json({ ok: true, location: '/' });
}), function(err, req, res, next) {
  if (err.status !== 401) { return next(err); }
  res.json({ ok: false, location: '/login' });
};

router.post('/logout', function(req, res, next) {
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/');
  });
});

router.get('/signup', function(req, res, next) {
  res.render('signup');
});

router.post('/signup/public-key/challenge', function(req, res, next) {
  db.run('INSERT INTO users (username, name) VALUES (?, ?)', [
    req.body.username,
    req.body.name,
  ], function(err) {
    if (err) { return next(err); }
    var user = {
      id: this.lastID,
      username: req.body.username,
      name: req.body.name
    };
    var challenge = '1234'; // TODO: Make this random,
    res.json({ user: user, challenge: challenge });
  });
});

module.exports = router;
