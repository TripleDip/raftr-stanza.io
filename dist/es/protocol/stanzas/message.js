import * as NS from '../namespaces';
const internals = {};
internals.defineMessage = function(JXT, name, namespace) {
    const Utils = JXT.utils;
    JXT.define({
        element: 'message',
        fields: {
            $body: {
                get: function getBody$() {
                    return Utils.getSubLangText(this.xml, namespace, 'body', this.lang);
                }
            },
            archiveId: {
                get: function getArchiveId() {
                    return Utils.getSubAttribute(this.xml, NS.MAM_TMP, 'archived', 'id');
                }
            },
            attachment: {
                get: function getAttachment() {
                    const attachmentObj = {
                        dispay_width: Utils.getSubAttribute(
                            this.xml,
                            namespace,
                            'attachment',
                            'dispay_width'
                        ),
                        display_height: Utils.getSubAttribute(
                            this.xml,
                            namespace,
                            'attachment',
                            'display_height'
                        ),
                        type: Utils.getSubAttribute(this.xml, namespace, 'attachment', 'type')
                    };
                    const attachmentXml = Utils.find(this.xml, namespace, 'attachment');
                    if (attachmentXml[0]) {
                        attachmentObj.url = Utils.getSubText(attachmentXml[0], namespace, 'url');
                        const thumbnailXml = Utils.find(attachmentXml[0], namespace, 'thumbnail');
                        if (thumbnailXml[0]) {
                            attachmentObj.thumbnailUrl = Utils.getSubText(
                                thumbnailXml[0],
                                namespace,
                                'url'
                            );
                        }
                    }
                    return attachmentXml[0] ? attachmentObj : null;
                },
                set: function setAttachment(value) {
                    const attachment = Utils.createElement('', 'attachment');
                    const thumbnail = Utils.createElement('', 'thumbnail');
                    const url = Utils.createElement('', 'url');
                    const tUrl = Utils.createElement('', 'url');
                    attachment.setAttribute('type', value.type);
                    attachment.setAttribute('dispay_width', value.width);
                    attachment.setAttribute('display_height', value.height);
                    url.textContent = value.url;
                    tUrl.textContent = value.thumbnailUrl;
                    if (value.url) {
                        thumbnail.appendChild(tUrl);
                        attachment.appendChild(thumbnail);
                        attachment.appendChild(url);
                        this.xml.appendChild(attachment);
                    }
                }
            },
            attention: Utils.boolSub(NS.ATTENTION_0, 'attention'),
            body: {
                get: function getBody() {
                    const bodies = this.$body;
                    return bodies[this.lang] || '';
                },
                set: function setBody(value) {
                    Utils.setSubLangText(this.xml, namespace, 'body', value, this.lang);
                }
            },
            chatState: Utils.enumSub(NS.CHAT_STATES, [
                'active',
                'composing',
                'paused',
                'inactive',
                'gone'
            ]),
            deleted: Utils.textSub(namespace, 'deleted'),
            from: Utils.jidAttribute('from', true),
            id: Utils.attribute('id'),
            lang: Utils.langAttribute(),
            parentThread: Utils.subAttribute(namespace, 'thread', 'parent'),
            receipt: Utils.subAttribute(NS.RECEIPTS, 'received', 'id'),
            replace: Utils.subAttribute(NS.CORRECTION_0, 'replace', 'id'),
            requestReceipt: Utils.boolSub(NS.RECEIPTS, 'request'),
            subject: Utils.textSub(namespace, 'subject'),
            thread: Utils.textSub(namespace, 'thread'),
            to: Utils.jidAttribute('to', true),
            type: Utils.attribute('type', 'normal')
        },
        name: name,
        namespace: namespace,
        topLevel: true
    });
};
export default function(JXT) {
    internals.defineMessage(JXT, 'message', NS.CLIENT);
    internals.defineMessage(JXT, 'serverMessage', NS.SERVER);
    internals.defineMessage(JXT, 'componentMessage', NS.COMPONENT);
}
