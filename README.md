# password-safe

Read and write '[Password Safe Database](http://pwsafe.org/)'. Write support not implemented yet.

[![build status](https://secure.travis-ci.org/dol/node-passwordsafe.png)](http://travis-ci.org/dol/node-passwordsafe)

# example

## load.js

```js
var PasswordSafe = require('password-safe');
var PasswordDb = require('fs').readFileSync('my.psafe3');

var Safe = new PasswordSafe({
    password: 'dbPassword',
});

Safe.load(PasswordDb, function(err, headerRecord, databaseRecords) {
    for (var i = 0; i < databaseRecords.length; i++) {
        var record = databaseRecords[i];
        console.log("Username: " + record.getUsername());
        console.log("Password: " + record.getPassword());
        console.log("-----------------");
    }
}
```

Output

```
Username: myusername1
Password: mypassword1
-----------------
Username: myusername2
Password: mypassword2
-----------------
```

## store.js

```js
var PasswordSafe = require('password-safe');
var PasswordDb = require('fs').readFileSync('my.psafe3');

var Safe = new PasswordSafe({
    password: 'dbPassword',
});

var headerRecord = safe.createHeaderRecord();
var databaseRecords = [
    safe.createDatabaseRecord('title1', 'my first password entry')
];
var encryptedData = safe.store(headerRecord, databaseRecords);
fs.writeFile('my_safe.psafe3', encryptedData);
```

Note: There are some setters missing for the header and database fields.

# install

With [npm](http://npmjs.org) do:

```
npm install password-safe
```

to get the command.

# license

MIT
