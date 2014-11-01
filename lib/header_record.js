'use strict';

var util = require('util');
var BaseRecord = require('./base_record');

function HeaderRecord(rawFields) {
    HeaderRecord.super_.call(this, rawFields);
    // See doc/formatV3.txt for more details
    // Name                        Value        Type    Implemented      Comments
    // --------------------------------------------------------------------------
    // Version                     0x00        2 bytes       Y              [1]
    // UUID                        0x01        UUID          Y              [2]
    // Non-default preferences     0x02        Text          Y              [3]
    // Tree Display Status         0x03        Text          Y              [4]
    // Timestamp of last save      0x04        time_t        Y              [5]
    // Who performed last save     0x05        Text          Y   [DEPRECATED 6]
    // What performed last save    0x06        Text          Y              [7]
    // Last saved by user          0x07        Text          Y              [8]
    // Last saved on host          0x08        Text          Y              [9]
    // Database Name               0x09        Text          Y              [10]
    // Database Description        0x0a        Text          Y              [11]
    // Database Filters            0x0b        Text          Y              [12]
    // Reserved                    0x0c        -                            [13]
    // Reserved                    0x0d        -                            [13]
    // Reserved                    0x0e        -                            [13]
    // Recently Used Entries       0x0f        Text                         [14]
    // Named Password Policies     0x10        Text                         [15]
    // Empty Groups                0x11        Text                         [16]
    // Yubico                      0x12        Text                         [13]
    // End of Entry                0xff        [empty]       Y              [17]
}

util.inherits(HeaderRecord, BaseRecord);

HeaderRecord.prototype.getVersion = function() {
    if (!(0x00 in this.rawFields)) {
        return null;
    }
    return this.rawFields[0x00].readUInt16LE(0);
};

HeaderRecord.prototype.getUUID = function() {
    return this.getUUIDField(0x02);
};

HeaderRecord.prototype.getNonDefaultPreferences = function() {
    return this.getTextField(0x02);
};

HeaderRecord.prototype.getTreeDisplayStatus  = function() {
    return this.getTextField(0x03);
};

HeaderRecord.prototype.getLastSaveTime = function() {
    return this.getDateField(0x04);
};

HeaderRecord.prototype.getLastSaveUserOld = function() {
    return this.getTextField(0x05);
};

HeaderRecord.prototype.getLastSaveApp = function() {
    return this.getTextField(0x06);
};

HeaderRecord.prototype.getLastSaveUser = function() {
    return this.getTextField(0x07);
};

HeaderRecord.prototype.getLastSaveHostname = function() {
    return this.getTextField(0x08);
};

HeaderRecord.prototype.getDatabaseName = function() {
    return this.getTextField(0x09);
};

HeaderRecord.prototype.getDatabaseDescription = function() {
    return this.getTextField(0x0a);
};

HeaderRecord.prototype.getDatabaseFilters = function() {
    return this.getTextField(0x0b);
};

HeaderRecord.prototype.getRecentlyUsedEntries = function() {
    return this.getTextField(0x0f);
};

HeaderRecord.prototype.getPasswordPolicies = function() {
    return this.getTextField(0x10);
};

HeaderRecord.prototype.getEmptyGroups = function() {
    return this.getTextField(0x11);
};

HeaderRecord.prototype.getYubico = function() {
    return this.getTextField(0x12);
};

module.exports = HeaderRecord;
