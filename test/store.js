var should = require('should');
var PasswordSafe = require('..');
var fs = require('fs');
var psafe3Data = fs.readFileSync(__dirname + '/data/test_new.psafe3');

describe('Loading the test database, store records with new password and load it again', function() {
    it('should be successful with the password \'123456\'', function(done) {
        var safe = new PasswordSafe({
            password: '123456'
        });

        var newSafe = new PasswordSafe({
            password: 'new123456'
        });

        safe.load(psafe3Data, function(err, headerRecord, databaseRecords) {
            should.not.exist(err);
            should.exist(databaseRecords);
            should.exist(headerRecord);

            var encryptedData = newSafe.store(headerRecord, databaseRecords);
            newSafe.load(encryptedData, function(newErr, newHeaderRecord, newDatabaseRecords) {
                should.not.exist(newErr);
                should.exist(newDatabaseRecords);
                should.exist(newHeaderRecord);

                newDatabaseRecords.should.be.instanceof(Array);
                newDatabaseRecords.should.have.lengthOf(3);
                done();
            });
        });
    });
});
