var express = require('express');
//var db = require('../db');
var router = express.Router();

/* GET users listing. */
router.get('/new', function(req, res, next) {
  res.render('register');
});

router.post('/', function(req, res, next) {
  console.log('REGISTER!');
  console.log(req.headers);
  console.log(req.body);
  
  
  res.json({ ok: true });
  
});

module.exports = router;
