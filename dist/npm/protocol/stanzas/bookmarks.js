"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const NS = tslib_1.__importStar(require("../namespaces"));
function default_1(JXT) {
    const Utils = JXT.utils;
    const Conference = JXT.define({
        element: 'conference',
        fields: {
            autoJoin: Utils.boolAttribute('autojoin'),
            jid: Utils.jidAttribute('jid'),
            name: Utils.attribute('name'),
            nick: Utils.textSub(NS.BOOKMARKS, 'nick')
        },
        name: '_conference',
        namespace: NS.BOOKMARKS
    });
    const Bookmarks = JXT.define({
        element: 'storage',
        name: 'bookmarks',
        namespace: NS.BOOKMARKS
    });
    JXT.extend(Bookmarks, Conference, 'conferences');
    JXT.withDefinition('query', NS.PRIVATE, function (PrivateStorage) {
        JXT.extend(PrivateStorage, Bookmarks);
    });
}
exports.default = default_1;
