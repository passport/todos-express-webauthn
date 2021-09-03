var express = require('express');
var passport = require('passport');
var cose2jwk = require('cose-to-jwk');
var jwk2pem = require('jwk-to-pem');
var cbor = require('cbor');
var base64url = require('base64url');
var db = require('../db');
var router = express.Router();

router.post('/request', function(req, res, next) {
  console.log('CHALLENGE!');
  console.log(req.headers);
  console.log(req.body);
  
  // TODO: Look up authenticators by username/id
  
  var opts = {
    challenge: '5678', // TODO: Make this random,
    
    allowCredentials: [ {
      type: 'public-key',
      //id: 'p5XN9H3kPWVymj0GcGDZtElg2Y2g4AISMWyUjjz3HEZBeHjamcknUsyTDy15zEGRXJCsyFVAEQ8Aq8_PbdkZnw',
      //id: 'jWcLBKE7CnLmJTecFZNTSFnWyaokRzpu3cg-b1qMBweUpCHMPhZ9MVL4oVFI3Vb4_K-d4wJoxfjjZ4uU17xNQA',
      //id: 'Vj1ZA6yKxblqKMhVduxJdOUt9tdz6333z7vygjM6qj8ZMc07m3tyGHwGYRDBOPl1PGRqHxdRQraYbaTjC7p0NQ',
      id: 'JYrR3EvvQJNqG0i_OwJckOkbzq4YJWviotG4hig9wA_Qdxm-eBEHfsYqBJKTtXMasL-RD9CFOlcag48icK3E8Q',
      //id: 'n90ZI-FwPA9HT5jtZins33Rtae1Zz1zLnoDR9yCj5Jwz2PB6fJR0KCPZehORB-ht48mRfbcA512cnDyfbQQ0OQ'
      //id: 'i18s3M25qA39Y6vOXR2_TOCglKz8kxFHHzx6Jpnk_Y9THMVBV85Vnd5IyjtNpFIS6Sp_ssg4ZJtAW6UARMStUQ',
      //id: 'AIJBqkpwDr_4baNTt2_u_kG-sGqZnr4WZ63y911uY9qB6u6JTcB-9MQkyQzruTOBRi9vKluqAZqBWio2tFem-SgrUD7RI7i_Bpajs5N6uG_cCdycJwE-4Xjt',
      //id: 'Abqu4O_U5dE71w4TuJ-zW1IrpdCgZftpnR-hKqfTWheMc8SZIaky7qXAyiDzPSqRtPUC',
      //id: 'AcZZ65l8zcISWWFOdY5Era6WnZPK5E-CBvo-qPlZas7KbvyKOj_LTBMuJkwsyqs8P38J',
      //id: 'AcQm4Bg7BONKr6OWOuCkMRUF8Z7UGkkEfqkEeoy1DmLW7Lp1f7zxYxpjI-2wtV9FlRiV',
      //id: 'AR3tgY3DAncMTt179Kcg-G_FdWu1E2eOqKXB_OtwaTJ-YITN8vvCST1qIWpirqQ1t93q'
      //id: 'GU0lmsssQL3nKuu3Q5YtBTVfTLUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      //id: '123',
      //transports: ['usb', 'nfc', 'ble']
      transports: ['usb', 'nfc', 'ble']
    } ]
  };
  
  res.json(opts);
});


router.post('/create', function(req, res, next) {
  console.log('REGISTER!');
  console.log(req.headers);
  console.log(req.body);
  
  /*
  db.run('INSERT INTO users (username, name) VALUES (?, ?)', [
    req.body.username,
    req.body.name
  ], function(err) {
    if (err) { return next(err); }
    */
    var opts = {
      challenge: '1234', // TODO: Make this random,
      rp: {
          name: "ACME Corporation"
      },
      user: {
        //id: this.lastID.toString(),
        //name: req.body.username,
        //displayName: req.body.name
        id: '1',
        name: 'alice',
        displayName: 'Alice Smith'
      },
      pubKeyCredParams: [
        {
          type: "public-key", alg: -7 // "ES256" IANA COSE Algorithms registry
        }
      ],
      attestation: 'indirect'
    }
    
    res.json(opts);
  //});
});

module.exports = router;
