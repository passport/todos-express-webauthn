var db = require('../db');


module.exports = function() {

  db.serialize(function() {
    db.run("CREATE TABLE IF NOT EXISTS users ( \
      username TEXT UNIQUE, \
      hashed_password BLOB, \
      salt BLOB, \
      name TEXT \
    )");
  });
  
  db.run("CREATE TABLE IF NOT EXISTS public_key_credentials ( \
    external_id TEXT UNIQUE, \
    public_key TEXT, \
    user_id INTEGER NOT NULL \
  )");

  //db.close();

};
