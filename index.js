'use strict';

var util = require('./lib/utils');
var Binary = require('binary');
var Buffer = require('buffer').Buffer;
var BufferEqual = require('buffer-equal');
var crypto = require('crypto');
var DatabaseRecord = require('./lib/database_record');
var HeaderRecord = require('./lib/header_record');
var TwoFish = require('triplesec').ciphers.TwoFish;
var UUID = require('node-uuid');
var WordArray = require('triplesec').WordArray;

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
        return BufferEqual(hashStretchedPassword, calcHashStretchedPassword);
    };

    var checkHmac = function(hmacSHA256, hmacExpected) {
        // Finish the stream to calculate the hmac hash
        hmacSHA256.end();
        return BufferEqual(hmacSHA256.read(), hmacExpected);
    };

    var reduceKey = function(stretchedPassword, bA, bB) {
        var twoFish = new TwoFish(WordArray.from_buffer(stretchedPassword));
        var bAWordArray = WordArray.from_buffer(bA);
        var bBWordArray = WordArray.from_buffer(bB);
        // The data will be decrypted and replaces the old data
        twoFish.decryptBlock(bAWordArray.words);
        twoFish.decryptBlock(bBWordArray.words);
        // Combine and return
        return bAWordArray.concat(bBWordArray);
    };

    var deriveKey = function(stretchedPassword, key) {
        var twoFish = new TwoFish(WordArray.from_buffer(stretchedPassword));
        var bAWordArray = WordArray.from_buffer(key.slice(0, 16));
        var bBWordArray = WordArray.from_buffer(key.slice(16));
        // The data will be encrypted and replaces the old data
        twoFish.encryptBlock(bAWordArray.words);
        twoFish.encryptBlock(bBWordArray.words);
        // Combine and return
        return bAWordArray.concat(bBWordArray).to_buffer();
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

        var sizeAndTypeLenght = 5;
        var twoFishBlockSize = TwoFish.prototype.blockSize;
        if (fieldLength <= twoFishBlockSize - sizeAndTypeLenght) {
            fieldData = fistBlock.slice(sizeAndTypeLenght, sizeAndTypeLenght + fieldLength);
        } else {
            fieldData = fistBlock.slice(sizeAndTypeLenght, twoFishBlockSize);
            fieldLength -= twoFishBlockSize - sizeAndTypeLenght;
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

    self.load = function(databaseBuffer, callback) {
        var parsedData = Binary.parse(databaseBuffer)
            .buffer('tag', 4)
            .buffer('salt', 32)
            .word32lu('iterations')
            .buffer('hashStretchedPassword', 32)
            .buffer('b1', 16)
            .buffer('b2', 16)
            .buffer('b3', 16)
            .buffer('b4', 16)
            .buffer('iv', 16)
            .buffer('encryptedData', databaseBuffer.length - 200)
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

        var dataKey = reduceKey(stretchedPassword, parsedData.b1, parsedData.b2);
        var hmacKey = reduceKey(stretchedPassword, parsedData.b3, parsedData.b4);

        var hmacSHA256 = crypto.createHmac('sha256', hmacKey.to_buffer());

        var decryptor = util.DecryptorTwoFishCBC(dataKey, parsedData.iv);

        var encryptedDataParser = Binary.parse(parsedData.encryptedData);

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
                    databaseRecords.push(recordObj);
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

        callback(null, headerRecord, databaseRecords);
    };

    var packData = function(headerRecord, databaseRecords, password) {
        var tag = new Buffer('PWS3', 'ascii');
        var salt = crypto.randomBytes(32);
        var iterations = 2048;
        var iterationsBuffer = new Buffer(4);
        iterationsBuffer.writeUInt32LE(iterations, 0);
        // May increase in the future => make is configurable
        var stretchedPassword = stretchPassword(
            password,
            salt,
            iterations
        );
        var hashStretchedPassword = crypto.createHash('sha256').update(stretchedPassword).digest();

        var dataKey = crypto.randomBytes(32);
        var hmacKey = crypto.randomBytes(32);

        var derivedDataKey = deriveKey(stretchedPassword, dataKey);

        var derivedHmacKey = deriveKey(stretchedPassword, hmacKey);

        var hmacSHA256 = crypto.createHmac('sha256', hmacKey);

        var iv = crypto.randomBytes(16);

        var encryptor = util.EncryptorTwoFishCBC(WordArray.from_buffer(dataKey), iv);

        var headerRawFields = headerRecord.getRawFields();

        // Make sure the 'end of entry' field is always last
        delete headerRawFields[0xff];
        headerRawFields[0xff] = new Buffer(0);

        var encryptedHeaderFields = [];
        for (var headerFieldType in headerRawFields) {
            if ((0x11).toString() === headerFieldType) {
                var emptyGroupsFields = headerRawFields[headerFieldType];
                for (var emptyGroupId in emptyGroupsFields) {
                    hmacSHA256.write(emptyGroupsFields[emptyGroupId]);
                    encryptedHeaderFields.push(writeField(headerFieldType, emptyGroupsFields[emptyGroupId], encryptor));
                }
            } else {
                hmacSHA256.write(headerRawFields[headerFieldType]);
                encryptedHeaderFields.push(writeField(headerFieldType, headerRawFields[headerFieldType], encryptor));
            }
        }

        var encryptedHeaderRecord = Buffer.concat(encryptedHeaderFields);

        var encryptedDatabaseFields = [];
        for (var recordId in databaseRecords) {
            var databaseRawFields = databaseRecords[recordId].getRawFields();
            // Make sure the 'end of entry' field is always last
            delete databaseRawFields[0xff];
            databaseRawFields[0xff] = new Buffer(0);
            for (var databaseFieldType in databaseRawFields) {
                hmacSHA256.write(databaseRawFields[databaseFieldType]);
                encryptedDatabaseFields.push(writeField(databaseFieldType, databaseRawFields[databaseFieldType], encryptor));
            }
        }

        var eof = new Buffer('PWS3-EOFPWS3-EOF', 'ascii');

        // Close hmac to generate the finale hash
        hmacSHA256.end();

        var packedData = Buffer.concat([
            tag,
            salt,
            iterationsBuffer,
            hashStretchedPassword,
            derivedDataKey,
            derivedHmacKey,
            iv,
            encryptedHeaderRecord,
            Buffer.concat(encryptedDatabaseFields),
            eof,
            hmacSHA256.read(),
        ]);

        return packedData;
    };

    var writeBlock = function(block, encryptor) {
        var blockWordArray = WordArray.from_buffer(block.slice(0, TwoFish.prototype.blockSize));

        var encryptBlock = new WordArray(encryptor
            .finalize(blockWordArray)
            .words
        );
        return encryptBlock.to_buffer();
    };

    var writeField = function(headerFieldType, data, encryptor) {
        var encryptedBlocks = [];

        var twoFishBlockSize = TwoFish.prototype.blockSize;
        var sizeAndTypeLenght = 5;
        var fieldLength = sizeAndTypeLenght + data.length;

        // Round up to the next multiplier of the twofish block size (16 bytes) up with random bytes.
        var blockData = crypto.randomBytes(Math.ceil(fieldLength / twoFishBlockSize) * twoFishBlockSize);
        blockData.writeUInt32LE(data.length, 0);
        blockData.writeUInt8(headerFieldType, 4);
        data.copy(blockData, sizeAndTypeLenght);

        while (blockData.length > 0) {
            encryptedBlocks.push(writeBlock(blockData, encryptor).slice(0, TwoFish.prototype.blockSize));
            blockData = blockData.slice(twoFishBlockSize);
        }
        return Buffer.concat(encryptedBlocks);
    };

    self.store = function(headerRecord, databaseRecords) {
        return packData(headerRecord, databaseRecords, opts.password);
    };

    self.createHeaderRecord = function() {
        var headerRecord = new HeaderRecord();
        headerRecord.setVersion(0x030d);
        return headerRecord;
    };

    self.createDatabaseRecord = function(title, password) {
        var databaseRecord = new DatabaseRecord();
        databaseRecord.setTitle(title);
        databaseRecord.setPassword(password);
        databaseRecord.setUUID(UUID.v4());
        return databaseRecord;
    };

}

module.exports = PasswordSafe;
