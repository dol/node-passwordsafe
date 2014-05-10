# password-safe

Read and write '[Password Safe Database](http://pwsafe.org/)'. Write support not implemented yet.

# example

## read.js

```js
var PasswordSafe = require('password-safe');
var PasswordSafeUtil = require('password-safe/utils');
var PasswordDb = require('fs').readFileSync('my.psafe3');


var Safe = new PasswordSafe({
    password: 'dbPassword',
});


Safe.load(PasswordDb, function(err, records) {
    for(var record in records) {
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

# install

With [npm](http://npmjs.org) do:

```
npm install password-safe
```

to get the command.

# license

MIT
