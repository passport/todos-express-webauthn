var express = require('express');
var db = require('../db');
var router = express.Router();

/* GET users listing. */
router.get('/new', function(req, res, next) {
  res.render('register');
});

router.post('/', function(req, res, next) {
  console.log('REGISTER!');
  console.log(req.headers);
  console.log(req.body);
  
  var user = {
    displayName: req.body.name,
    username: req.body.username
  };
  
  // FIXME: rename to users
  // use post to auto-assign an _id
  db.post(user, function callback(err, result) {
    console.log(err);
    console.log(result);
    
    if (err) { return next(err); }
    
    var opts = {
      challenge: '1234', // TODO: Make this random,
      rp: {
          name: "ACME Corporation"
      },
      user: {
        id: result.id,
        name: user.username,
        displayName: user.displayName
      },
      pubKeyCredParams: [
        {
          type: "public-key", alg: -7 // "ES256" IANA COSE Algorithms registry
        }
      ]
    }
    
    res.json(opts);
  });
});

module.exports = router;
