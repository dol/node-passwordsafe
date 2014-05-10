var util = require('./lib/utils');
var binary = require('binary');
var Buffer = require('buffer').Buffer;
var crypto = require('crypto');
var WordArray = require('triplesec').WordArray;
var TwoFish = require('triplesec').ciphers.TwoFish;
var bufferEqual = require('buffer-equal');
var Record = require('./lib/record');

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
        0x030A: 'V3.28',
        0x030B: 'V3.29',
        0x030C: 'V3.29Y',
        0x030D: 'V3.30',
    };

    if (typeof(opts) === 'undefined') {
        opts = {};
    }
    opts.password = opts.password || '';

    var stretchPassword = function(password, salt, interations) {
        var stretchedPassword = crypto
            .createHash('sha256')
            .update(password)
            .update(salt, 'binary')
            .digest();
        // Stretch password
        for (var i = 0; i < interations; i++) {
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
        // Todo: Replace with block size
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

        // Todo: Replace with block size
        var TwoFishBlockSize = TwoFish.prototype.blockSize;
        if (fieldLength <= TwoFishBlockSize - 5) {
            fieldData = fistBlock.slice(5, 5 + fieldLength);
        } else {
            fieldData = fistBlock.slice(5, TwoFishBlockSize);
            fieldLength -= TwoFishBlockSize - 5;
            while (fieldLength > 0) {
                var missingLength = Math.min(TwoFishBlockSize, fieldLength);
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
            .word32lu('interations')
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
            parsedData.interations
        );

        if (!checkPassword(stretchedPassword, parsedData.hashStretchedPassword)) {
            return callback('Wrong password provided.');
        }

        var dataKey = deriveKey(stretchedPassword, parsedData.b1, parsedData.b2);
        var hmacKey = deriveKey(stretchedPassword, parsedData.b3, parsedData.b4);

        var hmacSHA256 = crypto.createHmac('sha256', hmacKey.to_buffer());

        var decryptor = util.DecryptorTwoFishCBC(dataKey, parsedData.iv);

        var encryptedDataParser = binary.parse(parsedData.encryptedData);

        var headerRecords = [];
        // Read headers
        readHeaders: while (true) {
            var recordHeader = readField(encryptedDataParser, decryptor);
            switch (recordHeader.fieldType) {
                case 0xff:
                    break readHeaders;
                default:
                    hmacSHA256.write(recordHeader.fieldData);
                    headerRecords[recordHeader.fieldType] = recordHeader.fieldData;
                    break;
            }
        }

        var records = [];
        var currentRecord = [];
        readRecords: while (false === encryptedDataParser.eof()) {
            var recordData = readField(encryptedDataParser, decryptor);
            switch (recordData.fieldType) {
                case 0xff:
                    var recordObj = new Record(currentRecord);
                    records[recordObj.getUUID()] = recordObj;
                    currentRecord = [];
                    break;
                default:
                    hmacSHA256.write(recordData.fieldData);
                    currentRecord[recordData.fieldType] = recordData.fieldData;
                    break;
            }
        }

        if (!checkHmac(hmacSHA256, parsedData.hmac)) {
            return callback('Database integrity check (HMAC) went wrong.');
        }

        callback(null, records);
    };
}

module.exports = PasswordSafe;
