'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
function default_1(JXT) {
    const Utils = JXT.utils;
    const Attachment = JXT.define({
        element: 'attachment',
        fields: {
            dispay_width: Utils.attribute('dispay_width'),
            display_height: Utils.attribute('display_height'),
            type: Utils.attribute('type')
        },
        name: 'attachment',
        namespace: ''
    });
    JXT.extendMessage(Attachment);
}
exports.default = default_1;
