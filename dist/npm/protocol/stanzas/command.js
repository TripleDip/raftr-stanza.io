'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const tslib_1 = require('tslib');
const NS = tslib_1.__importStar(require('../namespaces'));
const ACTIONS = ['next', 'prev', 'complete', 'cancel'];
const CONDITIONS = [
    'bad-action',
    'bad-locale',
    'bad-payload',
    'bad-sessionid',
    'malformed-action',
    'session-expired'
];
function default_1(JXT) {
    const Utils = JXT.utils;
    const Command = JXT.define({
        element: 'command',
        fields: {
            action: Utils.attribute('action'),
            actions: {
                get: function() {
                    const result = [];
                    const actionSet = Utils.find(this.xml, NS.ADHOC_COMMANDS, 'actions');
                    if (!actionSet.length) {
                        return [];
                    }
                    for (const action of ACTIONS) {
                        const existing = Utils.find(actionSet[0], NS.ADHOC_COMMANDS, action);
                        if (existing.length) {
                            result.push(action);
                        }
                    }
                    return result;
                },
                set: function(values) {
                    const actionSet = Utils.findOrCreate(this.xml, NS.ADHOC_COMMANDS, 'actions');
                    for (let i = 0, len = actionSet.childNodes.length; i < len; i++) {
                        actionSet.removeChild(actionSet.childNodes[i]);
                    }
                    for (const value of values) {
                        actionSet.appendChild(
                            Utils.createElement(
                                NS.ADHOC_COMMANDS,
                                value.toLowerCase(),
                                NS.ADHOC_COMMANDS
                            )
                        );
                    }
                }
            },
            execute: Utils.subAttribute(NS.ADHOC_COMMANDS, 'actions', 'execute'),
            node: Utils.attribute('node'),
            sessionid: Utils.attribute('sessionid'),
            status: Utils.attribute('status')
        },
        name: 'command',
        namespace: NS.ADHOC_COMMANDS
    });
    const Note = JXT.define({
        element: 'note',
        fields: {
            type: Utils.attribute('type'),
            value: Utils.text()
        },
        name: '_commandNote',
        namespace: NS.ADHOC_COMMANDS
    });
    JXT.extend(Command, Note, 'notes');
    JXT.extendIQ(Command);
    JXT.withStanzaError(function(StanzaError) {
        JXT.add(StanzaError, 'adhocCommandCondition', Utils.enumSub(NS.ADHOC_COMMANDS, CONDITIONS));
    });
    JXT.withDataForm(function(DataForm) {
        JXT.extend(Command, DataForm);
    });
}
exports.default = default_1;
