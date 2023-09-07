var express = require('express');
var passport = require('passport');
var WebAuthnStrategy = require('passport-fido2-webauthn');
var SessionChallengeStore = require('passport-fido2-webauthn').SessionChallengeStore;
var ensureLogIn = require('connect-ensure-login').ensureLoggedIn;
var base64url = require('base64url');
var uuid = require('uuid').v4;
var db = require('../db');


var store = new SessionChallengeStore();

passport.use(new WebAuthnStrategy({ store: store }, function verify(id, userHandle, cb) {
  db.get('SELECT * FROM public_key_credentials WHERE external_id = ?', [ id ], function(err, row) {
    if (err) { return cb(err); }
    if (!row) { return cb(null, false, { message: 'Invalid key. '}); }
    var publicKey = row.public_key;
    db.get('SELECT * FROM users WHERE id = ?', [ row.user_id ], function(err, row) {
      if (err) { return cb(err); }
      if (!row) { return cb(null, false, { message: 'Invalid key. '}); }
      // TODO: how should userHandle be checked?
      //if (Buffer.compare(row.handle, userHandle) != 0) {
      if (userHandle && Buffer.compare(row.handle, userHandle) != 0) {
        return cb(null, false, { message: 'Invalid key. '});
      }
      return cb(null, row, publicKey);
    });
  });
}, function register(user, id, publicKey, cb) {
  db.get('SELECT * FROM users WHERE handle = ?', [ user.id ], function(err, localUser) {
    if (err) { return cb(err); }
    
    if (!localUser) {
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
    } else {
      db.run('INSERT INTO public_key_credentials (user_id, external_id, public_key) VALUES (?, ?, ?)', [
        localUser.id,
        id,
        publicKey
      ], function(err) {
        if (err) { return cb(err); }
        return cb(null, localUser);
      });
    }
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


var ensureLoggedIn = ensureLogIn();

var router = express.Router();

router.get('/login', function(req, res, next) {
  res.render('login');
});

function dumpBody(req, res, next) {
  console.log(req.body);
  next();
}

router.post('/login/public-key', dumpBody, passport.authenticate('webauthn', {
  failureMessage: true,
  failWithError: true
}), function(req, res, next) {
  res.json({ ok: true, location: '/' });
}, function(err, req, res, next) {
  var cxx = Math.floor(err.status / 100);
  if (cxx != 4) { return next(err); }
  res.json({ ok: false, location: '/login' });
});

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

// TODO: ensureLoggedIn shouldn't be used here, since its an API-like request, not redirect
router.post('/account/public-key/challenge', ensureLoggedIn, function(req, res, next) {
  db.get('SELECT * FROM users WHERE id = ?', [ req.user.id ], function(err, user) {
    if (err) { return next(err); }
    // TODO: handle no row
    res.locals.handle = user.handle;
    return next();
  });
}, function(req, res, next) {
  var user = {
    id: res.locals.handle,
    name: req.user.username,
    displayName: req.user.name
  };
  store.challenge(req, { user: user }, function(err, challenge) {
    if (err) { return next(err); }
    user.id = base64url.encode(user.id);
    res.json({ user: user, challenge: base64url.encode(challenge) });
  });
});

module.exports = router;
