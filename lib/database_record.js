function Record(rawFields) {
    var self = this;

    // See doc/formatV3.txt for more details
    // Name                        Value        Type    Implemented      Comments
    // --------------------------------------------------------------------------
    // UUID                        0x01        UUID          Y              [1]
    // Group                       0x02        Text          Y              [2]
    // Title                       0x03        Text          Y
    // Username                    0x04        Text          Y
    // Notes                       0x05        Text          Y
    // Password                    0x06        Text          Y              [3,4]
    // Creation Time               0x07        time_t        Y              [5]
    // Password Modification Time  0x08        time_t        Y              [5]
    // Last Access Time            0x09        time_t        Y              [5,6]
    // Password Expiry Time        0x0a        time_t        Y              [5,7]
    // *RESERVED*                  0x0b        4 bytes       -              [8]
    // Last Modification Time      0x0c        time_t        Y              [5,9]
    // URL                         0x0d        Text          Y              [10]
    // Autotype                    0x0e        Text          Y              [11]
    // Password History            0x0f        Text          Y              [12]
    // Password Policy             0x10        Text          Y              [13]
    // Password Expiry Interval    0x11        4 bytes       Y              [14]
    // Run Command                 0x12        Text          Y
    // Double-Click Action         0x13        2 bytes       Y              [15]
    // EMail address               0x14        Text          Y              [16]
    // Protected Entry             0x15        1 byte        Y              [17]
    // Own symbols for password    0x16        Text          Y              [18]
    // Shift Double-Click Action   0x17        2 bytes       Y              [15]
    // Password Policy Name        0x18        Text          Y              [19]
    // Entry keyboard shortcut     0x19        4 bytes       Y              [20]
    // End of Entry                0xff        [empty]       Y              [21]
    self.rawFields = rawFields;
}

Record.prototype = {
    constructor: Record,
    getTextField: function(type) {
        if (!(type in this.rawFields)) {
            return null;
        }
        return this.rawFields[type].toString('utf-8');
    },
    getDateField: function(type) {
        if (!(type in this.rawFields)) {
            return null;
        }
        return new Date(this.rawFields[type].readUInt32LE(0) * 1000);
    },
    getUUID: function() {
        if (!(0x01 in this.rawFields)) {
            return null;
        }
        return this.rawFields[0x01].toString('hex');
    },
    getGroup: function() {
        return this.getTextField(0x02);
    },
    getTitle: function() {
        return this.getTextField(0x03);
    },
    getUsername: function() {
        return this.getTextField(0x04);
    },
    getNotes: function() {
        return this.getTextField(0x05);
    },
    getPassword: function() {
        return this.getTextField(0x06);
    },
    getCreationTime: function() {
        return this.getDateField(0x07);
    },
    getPasswordModificationTime: function() {
        return this.getDateField(0x08);
    },
    getLastAccessTime: function() {
        return this.getDateField(0x09);
    },
    getPasswordExpiryTime: function() {
        return this.getDateField(0x0A);
    },
    getLastModificationTime: function() {
        return this.getDateField(0x0C);
    },
    getUrl: function() {
        return this.getTextField(0x0D);
    },
    getAutotype: function() {
        return this.getTextField(0x0E);
    },
    getPasswordHistory: function() {
        return this.getTextField(0x0F);
    },
    getPasswordPolicy: function() {
        return this.getTextField(0x10);
    },
    getPasswordExpiryInterval: function() {
        if (!(0x11 in this.rawFields)) {
            return null;
        }
        return this.rawFields[0x11].readUInt32LE(0);
    },
    getRunCommand: function() {
        return this.getTextField(0x12);
    },
    getDoubleClickAction: function() {
        if (!(0x13 in this.rawFields)) {
            return null;
        }
        return this.rawFields[0x13].readUInt16LE(0);
    },
    getEMailAddress: function() {
        return this.getTextField(0x14);
    },
    getProtectedEntry: function() {
        if (!(0x15 in this.rawFields)) {
            return null;
        }
        return this.rawFields[0x15].readUInt8(0);
    },
    getOwnSymbolsForPassword: function() {
        return this.getTextField(0x16);
    },
    getShiftDoubleClickAction: function() {
        if (!(0x17 in this.rawFields)) {
            return null;
        }
        return this.rawFields[0x17].readUInt16LE(0);
    },
    getPasswordPolicyName: function() {
        return this.getTextField(0x18);
    },
    getEntryKeyboardShortcut: function() {
        if (!(0x19 in this.rawFields)) {
            return null;
        }
        return this.rawFields[0x19].readUInt16LE(0);
    }
};

module.exports = Record;
