var express = require('express');
var ensureLoggedIn = require('connect-ensure-login').ensureLoggedIn;
var db = require('../db');

var router = express.Router();

/* GET users listing. */
router.get('/',
  ensureLoggedIn(),
  function(req, res, next) {
    db.get('SELECT rowid AS id, username, name FROM users WHERE rowid = ?', [ req.user.id ], function(err, row) {
      if (err) { return next(err); }
    
      // TODO: Handle undefined row.
    
      var user = {
        id: row.id.toString(),
        username: row.username,
        displayName: row.name
      };
      res.render('profile', { user: user });
    });
  });

router.get('/security-keys',
  ensureLoggedIn(),
  function(req, res, next) {
    db.all('SELECT rowid as id, * FROM public_key_credentials WHERE user_id = ?', [ req.user.id ], function(err, rows) {
      if (err) { return next(err); }
      
      res.locals.securityKeys = [];
      
      rows.forEach(function(row, i) {
        // TODO: Better names
        var key = {
          id: row.id,
          name: 'Security Key ' + i,
        };
        
        res.locals.securityKeys.push(key);
      });
      
      next();
    });
  },
  function(req, res, next) {
    res.render('myaccount/securitykeys', { user: req.user });
  });

router.post('/security-keys/new',
  ensureLoggedIn(),
  function(req, res, next) {
    console.log('CREATE KEY FOR USER');
    console.log(req.user);
    
    res.format({
      'application/json': function () {
        var options = {
          challenge: '1234', // TODO: Make this random,
          rp: {
            name: "ACME Corporation"
          },
          user: {
            id: req.user.id,
            name: req.user.username,
            displayName: req.user.displayName
          },
          pubKeyCredParams: [
            {
              type: "public-key", alg: -7 // "ES256" IANA COSE Algorithms registry
            }
          ],
          attestation: 'none'
        }
      
        res.send(options);
      },

      default: function () {
        // TODO
      }
    });
  });



module.exports = router;
