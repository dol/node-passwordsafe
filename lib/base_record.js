'use strict';

var UUID = require('node-uuid');

function BaseRecord(rawFields) {
    this.setRawFields(rawFields);
}

BaseRecord.prototype.setRawFields =  function(rawFields) {
    var self = this;
    self.rawFields = rawFields instanceof Array ? rawFields : [];
};

BaseRecord.prototype.getRawFields = function() {
    return this.rawFields;
};

BaseRecord.prototype.getTextField =  function(type) {
    if (!(type in this.rawFields)) {
        return null;
    }
    return this.rawFields[type].toString('utf-8');
};

BaseRecord.prototype.setTextField =  function(type, text) {
    this.rawFields[type] = Buffer.from(text, 'utf-8');
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
    return UUID.unparse(this.rawFields[type]);
};

BaseRecord.prototype.setUUIDField = function(type, uuid) {
    if (typeof uuid === 'string' || uuid instanceof String) {
        var tmpUuidBuffer = Buffer.alloc(16);
        UUID.parse(uuid, tmpUuidBuffer);
        uuid = tmpUuidBuffer;
    }
    this.rawFields[type] = uuid;
};

module.exports = BaseRecord;
