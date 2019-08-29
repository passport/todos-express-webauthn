var PouchDB = require('pouchdb');
PouchDB.plugin(require('pouchdb-find'));

var db = new PouchDB('var/pouchdb/users');

/*
var idx = db.createIndex({ index: { fields: ['username'] } });

idx.then(function(ok) {
  console.log('INDEX CREATED!');
  console.log(ok);
}).catch(function(err) {
  console.log('INDEX ERROR');
  console.log(err);
})
*/

db.info().then(function (info) {
  console.log(info);
  
  db.allDocs({include_docs: true}).then(function (info) {
    console.log(info.rows);
  })
})

exports = module.exports = db;