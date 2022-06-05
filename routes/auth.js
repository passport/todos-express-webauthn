var express = require('express');
var passport = require('passport');
var WebAuthnStrategy = require('passport-webauthentication');
var SessionChallengeStore = require('passport-webauthentication').SessionChallengeStore;
var base64url = require('base64url');
var uuid = require('uuid').v4;
var db = require('../db');


var store = new SessionChallengeStore();

passport.use(new WebAuthnStrategy({ store: store }, function verify(id, userHandle, cb) {
  // TODO: verify user handle
  
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
}, function register(user, id, publicKey, cb) {
  db.run('INSERT INTO users (username, name, handle) VALUES (?, ?, ?)', [
    user.name,
    user.displayName,
    user.id
  ], function(err) {
    if (err) { return cb(err); }
    var newUser = {
      id: this.lastID,
      username: user.name,
      name: user.displayName
    };
    db.run('INSERT INTO public_key_credentials (user_id, external_id, public_key) VALUES (?, ?, ?)', [
      newUser.id,
      id,
      publicKey
    ], function(err) {
      if (err) { return cb(err); }
      return cb(null, newUser);
    });
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

router.post('/login/public-key/challenge', function(req, res, next) {
  store.challenge(req, function(err, challenge) {
    if (err) { return next(err); }
    res.json({ challenge: base64url.encode(challenge) });
  });
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

router.post('/signup/public-key/challenge', function(req, res, next) {
  var handle = Buffer.alloc(16);
  handle = uuid({}, handle);
  var user = {
    id: handle,
    name: req.body.username,
    displayName: req.body.name
  };
  store.challenge(req, { user: user }, function(err, challenge) {
    if (err) { return next(err); }
    user.id = base64url.encode(user.id);
    res.json({ user: user, challenge: base64url.encode(challenge) });
  });
});

module.exports = router;
