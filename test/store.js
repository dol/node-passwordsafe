var should = require('should');
var PasswordSafe = require('..');
var DatabaseRecord = require('../lib/database_record');
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
                should.exist(newHeaderRecord);
                should.exist(newDatabaseRecords);

                newDatabaseRecords.should.be.instanceof(Array);
                newDatabaseRecords.should.have.lengthOf(3);
                done();
            });
        });
    });
});

describe('Create minimal header record and store it. Try to load the record.', function() {
    it('should be successful with the password \'123456\'', function(done) {
        var safe = new PasswordSafe({
            password: '123456'
        });

        var headerRecord = safe.createMinimalHeaderRecord();
        var encryptedData = safe.store(headerRecord, []);

        safe.load(encryptedData, function(err, headerRecord, databaseRecords) {
            should.not.exist(err);
            should.exist(headerRecord);
            should.exist(databaseRecords);
            databaseRecords.should.have.lengthOf(0);
        });
        done();
    });
});


describe('Create minimal header record and store it with one database record. Try to load the record.', function() {
    it('should be successful with the password \'123456\'', function(done) {
        var safe = new PasswordSafe({
            password: '123456'
        });

        var headerRecord = safe.createMinimalHeaderRecord();
        var encryptedData = safe.store(headerRecord, [new DatabaseRecord()]);

        safe.load(encryptedData, function(err, headerRecord, databaseRecords) {
            should.not.exist(err);
            should.exist(headerRecord);
            should.exist(databaseRecords);
            databaseRecords.should.have.lengthOf(1);
        });
        done();
    });
});
