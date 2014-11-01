'use strict';

var util = require('./lib/utils');
var binary = require('binary');
var Buffer = require('buffer').Buffer;
var crypto = require('crypto');
var WordArray = require('triplesec').WordArray;
var TwoFish = require('triplesec').ciphers.TwoFish;
var bufferEqual = require('buffer-equal');
var DatabaseRecord = require('./lib/database_record');
var HeaderRecord = require('./lib/header_record');

function PasswordSafe(opts) {
    var self = this;

    self.versionMapping = {
        0x0300: 'V3.01',
        0x0301: 'V3.03',
        0x0302: 'V3.09',
        0x0303: 'V3.12',
        0x0304: 'V3.13',
        0x0305: 'V3.14',
        0x0306: 'V3.19',
        0x0307: 'V3.22',
        0x0308: 'V3.25',
        0x0309: 'V3.26',
        0x030a: 'V3.28',
        0x030b: 'V3.29',
        0x030c: 'V3.29Y',
        0x030d: 'V3.30',
    };

    if (typeof(opts) === 'undefined') {
        opts = {};
    }
    opts.password = opts.password || '';

    var stretchPassword = function(password, salt, iterations) {
        var stretchedPassword = crypto
            .createHash('sha256')
            .update(password)
            .update(salt, 'binary')
            .digest();
        // Stretch password
        for (var i = 0; i < iterations; i++) {
            stretchedPassword = crypto.
            createHash('sha256').
            update(stretchedPassword).
            digest();
        }
        return stretchedPassword;
    };

    var checkPassword = function(stretchedPassword, hashStretchedPassword) {
        var calcHashStretchedPassword = crypto.createHash('sha256').update(stretchedPassword).digest();
        return bufferEqual(hashStretchedPassword, calcHashStretchedPassword);
    };

    var checkHmac = function(hmacSHA256, hmacExpected) {
        // Finish the stream to calculate the hmac hash
        hmacSHA256.end();
        return bufferEqual(hmacSHA256.read(), hmacExpected);
    };

    var deriveKey = function(stretchedPassword, bA, bB) {
        var twoFish = new TwoFish(WordArray.from_buffer(stretchedPassword));
        var bAWordArray = WordArray.from_buffer(bA);
        var bBWordArray = WordArray.from_buffer(bB);
        // The data will be encrypted and replaces the old data
        twoFish.decryptBlock(bAWordArray.words);
        twoFish.decryptBlock(bBWordArray.words);
        // Combine and return
        return bAWordArray.concat(bBWordArray);
    };

    var readBlock = function(binaryParser, decryptor) {
        var blockWordArray = WordArray.from_buffer(
            binaryParser
            .buffer('block', TwoFish.prototype.blockSize)
            .vars
            .block
        );

        var decryptBlock = new WordArray(decryptor
            .finalize(blockWordArray)
            .words
        );
        return decryptBlock.to_buffer();
    };

    var readField = function(binaryParser, decryptor) {
        var fistBlock = readBlock(binaryParser, decryptor);
        var fieldLength = fistBlock.readUInt32LE(0);
        var fieldType = fistBlock.readUInt8(4);
        var fieldData;

        var twoFishBlockSize = TwoFish.prototype.blockSize;
        if (fieldLength <= twoFishBlockSize - 5) {
            fieldData = fistBlock.slice(5, 5 + fieldLength);
        } else {
            fieldData = fistBlock.slice(5, twoFishBlockSize);
            fieldLength -= twoFishBlockSize - 5;
            while (fieldLength > 0) {
                var missingLength = Math.min(twoFishBlockSize, fieldLength);
                fieldData = Buffer.concat(
                    [
                        fieldData,
                        readBlock(binaryParser, decryptor).slice(0, missingLength)
                    ]
                );
                fieldLength -= missingLength;
            }
        }

        return {
            fieldType: fieldType,
            fieldData: fieldData,
        };
    };

    self.load = function(dbBuffer, callback) {
        var parsedData = binary.parse(dbBuffer)
            .buffer('tag', 4)
            .buffer('salt', 32)
            .word32lu('iterations')
            .buffer('hashStretchedPassword', 32)
            .buffer('b1', 16)
            .buffer('b2', 16)
            .buffer('b3', 16)
            .buffer('b4', 16)
            .buffer('iv', 16)
            .buffer('encryptedData', dbBuffer.length - 200)
            .buffer('eof', 16)
            .buffer('hmac', 32)
            .vars;

        if ('PWS3-EOFPWS3-EOF' !== parsedData.eof.toString()) {
            return callback('Invalid database format.');
        }
        var stretchedPassword = stretchPassword(
            opts.password,
            parsedData.salt,
            parsedData.iterations
        );

        if (!checkPassword(stretchedPassword, parsedData.hashStretchedPassword)) {
            return callback('Wrong password provided.');
        }

        var dataKey = deriveKey(stretchedPassword, parsedData.b1, parsedData.b2);
        var hmacKey = deriveKey(stretchedPassword, parsedData.b3, parsedData.b4);

        var hmacSHA256 = crypto.createHmac('sha256', hmacKey.to_buffer());

        var decryptor = util.DecryptorTwoFishCBC(dataKey, parsedData.iv);

        var encryptedDataParser = binary.parse(parsedData.encryptedData);

        var headerRawFields = [];
        // Read headers
        readHeaders: while (true) {
            var headerField = readField(encryptedDataParser, decryptor);
            hmacSHA256.write(headerField.fieldData);
            switch (headerField.fieldType) {
                case 0xff:
                    break readHeaders;
                case 0x11:
                    if (!(0x11 in headerRawFields)) {
                        headerRawFields[0x11] = [];
                    }
                    headerRawFields[0x11].push(headerField.fieldData);
                    break;
                default:
                    headerRawFields[headerField.fieldType] = headerField.fieldData;
                    break;
            }
        }

        var headerRecord = new HeaderRecord(headerRawFields);

        var databaseRecords = [];
        var currentRecord = [];
        readRecords: while (false === encryptedDataParser.eof()) {
            var recordData = readField(encryptedDataParser, decryptor);
            hmacSHA256.write(recordData.fieldData);
            switch (recordData.fieldType) {
                case 0xff:
                    var recordObj = new DatabaseRecord(currentRecord);
                    databaseRecords[recordObj.getUUID()] = recordObj;
                    currentRecord = [];
                    break;
                default:
                    currentRecord[recordData.fieldType] = recordData.fieldData;
                    break;
            }
        }

        if (!checkHmac(hmacSHA256, parsedData.hmac)) {
            return callback('Database integrity check (HMAC) went wrong.');
        }

        callback(null, databaseRecords, headerRecord);
    };

}

module.exports = PasswordSafe;
