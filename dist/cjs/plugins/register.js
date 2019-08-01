"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
function default_1(client) {
    client.getAccountInfo = function (jid, cb) {
        return this.sendIq({
            register: true,
            to: jid,
            type: 'get'
        }, cb);
    };
    client.updateAccount = function (jid, data, cb) {
        return this.sendIq({
            register: data,
            to: jid,
            type: 'set'
        }, cb);
    };
    client.deleteAccount = function (jid, cb) {
        return this.sendIq({
            register: {
                remove: true
            },
            to: jid,
            type: 'set'
        }, cb);
    };
}
exports.default = default_1;
