'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const tslib_1 = require('tslib');
const NS = tslib_1.__importStar(require('../namespaces'));
function default_1(JXT) {
    const Utils = JXT.utils;
    const Address = JXT.define({
        element: 'address',
        fields: {
            delivered: Utils.boolAttribute('delivered'),
            description: Utils.attribute('desc'),
            jid: Utils.jidAttribute('jid'),
            node: Utils.attribute('node'),
            type: Utils.attribute('type'),
            uri: Utils.attribute('uri')
        },
        name: '_address',
        namespace: NS.ADDRESS
    });
    const Addresses = Utils.subMultiExtension(NS.ADDRESS, 'addresses', Address);
    JXT.withMessage(function(Message) {
        JXT.add(Message, 'addresses', Addresses);
    });
    JXT.withPresence(function(Presence) {
        JXT.add(Presence, 'addresses', Addresses);
    });
}
exports.default = default_1;
