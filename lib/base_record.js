'use strict';

var uuid = require('node-uuid');

function BaseRecord(rawFields) {
    this.setRawFields(rawFields);
}

BaseRecord.prototype.setRawFields =  function(rawFields) {
    var self = this;
    self.rawFields = rawFields;
};

BaseRecord.prototype.getTextField =  function(type) {
    if (!(type in this.rawFields)) {
        return null;
    }
    return this.rawFields[type].toString('utf-8');
};

BaseRecord.prototype.getDateField = function(type) {
    if (!(type in this.rawFields)) {
        return null;
    }
    return new Date(this.rawFields[type].readUInt32LE(0) * 1000);
};

BaseRecord.prototype.getUUIDField = function(type) {
    if (!(type in this.rawFields)) {
        return null;
    }
    return uuid.unparse(this.rawFields[type]);
};

module.exports = BaseRecord;
