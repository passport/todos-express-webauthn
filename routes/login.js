var express = require('express');
var passport = require('passport');
var base64url = require('base64url');
var router = express.Router();

router.get('/login',
  function(req, res, next){
    res.render('login');
  });

router.post('/login',
  function(req, res, next){
    console.log('LOGIN');
    console.log(req.headers);
    console.log(req.body)
    
    res.format({
      'application/json': function () {
        var options = {
          challenge: '5678', // TODO: Make this random,
    
          /*
          allowCredentials: [ {
            type: 'public-key',
            //id: 'p5XN9H3kPWVymj0GcGDZtElg2Y2g4AISMWyUjjz3HEZBeHjamcknUsyTDy15zEGRXJCsyFVAEQ8Aq8_PbdkZnw',
            //id: 'jWcLBKE7CnLmJTecFZNTSFnWyaokRzpu3cg-b1qMBweUpCHMPhZ9MVL4oVFI3Vb4_K-d4wJoxfjjZ4uU17xNQA',
            //id: 'Vj1ZA6yKxblqKMhVduxJdOUt9tdz6333z7vygjM6qj8ZMc07m3tyGHwGYRDBOPl1PGRqHxdRQraYbaTjC7p0NQ',
            //id: 'JYrR3EvvQJNqG0i_OwJckOkbzq4YJWviotG4hig9wA_Qdxm-eBEHfsYqBJKTtXMasL-RD9CFOlcag48icK3E8Q',
            //id: 'n90ZI-FwPA9HT5jtZins33Rtae1Zz1zLnoDR9yCj5Jwz2PB6fJR0KCPZehORB-ht48mRfbcA512cnDyfbQQ0OQ'
            //id: 'i18s3M25qA39Y6vOXR2_TOCglKz8kxFHHzx6Jpnk_Y9THMVBV85Vnd5IyjtNpFIS6Sp_ssg4ZJtAW6UARMStUQ',
            //id: 'AIJBqkpwDr_4baNTt2_u_kG-sGqZnr4WZ63y911uY9qB6u6JTcB-9MQkyQzruTOBRi9vKluqAZqBWio2tFem-SgrUD7RI7i_Bpajs5N6uG_cCdycJwE-4Xjt',
            //id: 'Abqu4O_U5dE71w4TuJ-zW1IrpdCgZftpnR-hKqfTWheMc8SZIaky7qXAyiDzPSqRtPUC',
            //id: 'AcZZ65l8zcISWWFOdY5Era6WnZPK5E-CBvo-qPlZas7KbvyKOj_LTBMuJkwsyqs8P38J',
            //id: 'AcQm4Bg7BONKr6OWOuCkMRUF8Z7UGkkEfqkEeoy1DmLW7Lp1f7zxYxpjI-2wtV9FlRiV',
            //id: 'AR3tgY3DAncMTt179Kcg-G_FdWu1E2eOqKXB_OtwaTJ-YITN8vvCST1qIWpirqQ1t93q'
            //id: 'GU0lmsssQL3nKuu3Q5YtBTVfTLUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            //id: '123',
            //id: 'ARc4h0RwdGkBHuvD4XeYVRPCMh0U1GIZ7ByW39DUd2bxy5ue55OftYqzivcfrcABMXtr',
            //id: 'AcjZv01ljIwB4uxZrKUEEXTttjg2NEy2QkkvrF6QlWdatZ2CTBBVzXB6PHg1FR6KbMDr'
            //id: 'AbmCd_HL3HoNUM4OnQoxHbzx7n6RqJ6m1FrRqcuN2cx8B76wEUd-r3hITX2l8RUnfszD',
            id: 'ARRq0HnxomOUCSBwTuVa9PEIp7sEYQ7IdBaIzeEFFDgFQ0VzoDHlCcqYZSeEMDvbDA0N',
            //transports: ['usb', 'nfc', 'ble']
            transports: ['internal']
          } ]*/
        };
        
        res.send(options);
      },

      default: function () {
        // TODO
      }
    });
    
    
  });


router.post('/login/public-key',
  function(req, res, next) {
    console.log('RESPONSE!');
    console.log(req.headers);
    console.log(req.body);
    
    // https://www.w3.org/TR/webauthn/#registering-a-new-credential
    
    //var response = req.body.response;
    //var clientData = JSON.parse(base64url.decode(response.clientDataJSON));
    //console.log(clientData);
    
    next();
  },
  passport.authenticate('webauthn', { failureRedirect: '/login' }),
  function(req, res, next) {
    console.log('AUTHENTICATED!');
    //res.redirect('/');
    res.json({ ok: true });
  });
  
router.post('/login/public-key/2',
  // TODO: 403 if not logged in
  function(req, res, next) {
    console.log('RESPONSE!');
    console.log(req.headers);
    console.log(req.body);
    
    // https://www.w3.org/TR/webauthn/#registering-a-new-credential
    
    //var response = req.body.response;
    //var clientData = JSON.parse(base64url.decode(response.clientDataJSON));
    //console.log(clientData);
    
    next();
  },
  passport.authenticate('webauthn-2f', { failureRedirect: '/login' }),
  function(req, res, next) {
    console.log('AUTHENTICATED!');
    //res.redirect('/');
    res.json({ ok: true });
  });

module.exports = router;
