'use strict';
var TwoFish = require('triplesec').ciphers.TwoFish;
var WordArray = require('triplesec').WordArray;
var CryptoJS = require('crypto-js');
var BlockCipher = CryptoJS.lib.BlockCipher;

var generateTwoFishMod = function() {
    var TwoFishPrototype = TwoFish.prototype;
    // Hack. Copy/paste from BlockCipher.init()
    TwoFishPrototype.init = function(xformMode, key, cfg) {
        this.constructor(key);
        // Apply config defaults
        this.cfg = this.cfg.extend(cfg);

        // Store transform mode and key
        this._xformMode = xformMode;
        this._key = key;
        // Set initial values
        this.reset();
    };
    return BlockCipher.extend(TwoFish.prototype);
};

exports.DecryptorTwoFishCBC = function DecryptorTwoFishCBC(key, iv) {
    var TwoFishMod = generateTwoFishMod();

    return TwoFishMod.createDecryptor(key, {
        iv: WordArray.from_buffer(iv),
        mode: CryptoJS.mode.CBC
    });
};
exports.EncryptorTwoFishCBC = function EncryptorTwoFishCBC(key, iv) {
    var TwoFishMod = generateTwoFishMod();

    return TwoFishMod.createEncryptor(key, {
        iv: WordArray.from_buffer(iv),
        mode: CryptoJS.mode.CBC
    });
};

exports.mapRecordToObject = function mapRecordToObject(record) {
    var object                      = new Object({});
    object.uuid                     = record.getUUID();
    object.group                    = record.getGroup();
    object.title                    = record.getTitle();
    object.username                 = record.getUsername();
    object.notes                    = record.getNotes();
    object.password                 = record.getPassword();
    object.creationTime             = record.getCreationTime();
    object.passwordModificationTime = record.getPasswordModificationTime();
    object.lastAccessTime           = record.getLastAccessTime();
    object.passwordExpiryTime       = record.getPasswordExpiryTime();
    object.lastModificationTime     = record.getLastModificationTime();
    object.url                      = record.getUrl();
    object.autotype                 = record.getAutotype();
    object.passwordHistory          = record.getPasswordHistory();
    object.passwordPolicy           = record.getPasswordPolicy();
    object.passwordExpiryInterval   = record.getPasswordExpiryInterval();
    object.command                  = record.getRunCommand();
    object.doubleClickAction        = record.getDoubleClickAction();
    object.emailAddress             = record.getEMailAddress();
    object.protectedEntry           = record.getProtectedEntry();
    object.ownSymbolsForPassword    = record.getOwnSymbolsForPassword();
    object.shiftDoubleClickAction   = record.getShiftDoubleClickAction();
    object.passwordPolicyName       = record.getPasswordPolicyName();
    object.entryKeyboardShortcut    = record.getEntryKeyboardShortcut();

    return object;
};
