'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const tslib_1 = require('tslib');
const disco_1 = tslib_1.__importDefault(require('./disco'));
const discoonly_1 = tslib_1.__importDefault(require('./discoonly'));
const attention_1 = tslib_1.__importDefault(require('./attention'));
const avatar_1 = tslib_1.__importDefault(require('./avatar'));
const blocking_1 = tslib_1.__importDefault(require('./blocking'));
const bob_1 = tslib_1.__importDefault(require('./bob'));
const bookmarks_1 = tslib_1.__importDefault(require('./bookmarks'));
const carbons_1 = tslib_1.__importDefault(require('./carbons'));
const chatstates_1 = tslib_1.__importDefault(require('./chatstates'));
const command_1 = tslib_1.__importDefault(require('./command'));
const correction_1 = tslib_1.__importDefault(require('./correction'));
const csi_1 = tslib_1.__importDefault(require('./csi'));
const dataforms_1 = tslib_1.__importDefault(require('./dataforms'));
const extdisco_1 = tslib_1.__importDefault(require('./extdisco'));
const geoloc_1 = tslib_1.__importDefault(require('./geoloc'));
const invisible_1 = tslib_1.__importDefault(require('./invisible'));
const jidprep_1 = tslib_1.__importDefault(require('./jidprep'));
const jingle_1 = tslib_1.__importDefault(require('./jingle'));
const keepalive_1 = tslib_1.__importDefault(require('./keepalive'));
const logging_1 = tslib_1.__importDefault(require('./logging'));
const mam_1 = tslib_1.__importDefault(require('./mam'));
const markers_1 = tslib_1.__importDefault(require('./markers'));
const muc_1 = tslib_1.__importDefault(require('./muc'));
const mood_1 = tslib_1.__importDefault(require('./mood'));
const nick_1 = tslib_1.__importDefault(require('./nick'));
const ping_1 = tslib_1.__importDefault(require('./ping'));
const private_1 = tslib_1.__importDefault(require('./private'));
const push_1 = tslib_1.__importDefault(require('./push'));
const pubsub_1 = tslib_1.__importDefault(require('./pubsub'));
const reach_1 = tslib_1.__importDefault(require('./reach'));
const receipts_1 = tslib_1.__importDefault(require('./receipts'));
const register_1 = tslib_1.__importDefault(require('./register'));
const roster_1 = tslib_1.__importDefault(require('./roster'));
const rtt_1 = tslib_1.__importDefault(require('./rtt'));
const time_1 = tslib_1.__importDefault(require('./time'));
const vcard_1 = tslib_1.__importDefault(require('./vcard'));
const version_1 = tslib_1.__importDefault(require('./version'));
function default_1(client) {
    // We always need this one first
    client.use(disco_1.default);
    client.use(discoonly_1.default);
    client.use(attention_1.default);
    client.use(avatar_1.default);
    client.use(blocking_1.default);
    client.use(bob_1.default);
    client.use(bookmarks_1.default);
    client.use(carbons_1.default);
    client.use(chatstates_1.default);
    client.use(command_1.default);
    client.use(correction_1.default);
    client.use(csi_1.default);
    client.use(dataforms_1.default);
    client.use(extdisco_1.default);
    client.use(geoloc_1.default);
    client.use(invisible_1.default);
    client.use(jidprep_1.default);
    client.use(jingle_1.default);
    client.use(keepalive_1.default);
    client.use(logging_1.default);
    client.use(mam_1.default);
    client.use(markers_1.default);
    client.use(muc_1.default);
    client.use(mood_1.default);
    client.use(nick_1.default);
    client.use(ping_1.default);
    client.use(private_1.default);
    client.use(push_1.default);
    client.use(pubsub_1.default);
    client.use(reach_1.default);
    client.use(receipts_1.default);
    client.use(register_1.default);
    client.use(roster_1.default);
    client.use(rtt_1.default);
    client.use(time_1.default);
    client.use(vcard_1.default);
    client.use(version_1.default);
}
exports.default = default_1;
