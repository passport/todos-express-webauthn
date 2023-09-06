var express = require('express');
var ensureLogIn = require('connect-ensure-login').ensureLoggedIn;

var ensureLoggedIn = ensureLogIn();

var router = express.Router();

router.get('/account', ensureLoggedIn, function(req, res, next) {
  res.render('account', { user: req.user });
});

module.exports = router;
