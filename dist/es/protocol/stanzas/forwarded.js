import * as NS from '../namespaces';
export default function (JXT) {
    const Forwarded = JXT.define({
        element: 'forwarded',
        name: 'forwarded',
        namespace: NS.FORWARD_0
    });
    JXT.withMessage(function (Message) {
        JXT.extend(Message, Forwarded);
        JXT.extend(Forwarded, Message);
    });
    JXT.withPresence(function (Presence) {
        JXT.extend(Presence, Forwarded);
        JXT.extend(Forwarded, Presence);
    });
    JXT.withIQ(function (IQ) {
        JXT.extend(IQ, Forwarded);
        JXT.extend(Forwarded, IQ);
    });
    JXT.withDefinition('delay', NS.DELAY, function (Delayed) {
        JXT.extend(Forwarded, Delayed);
    });
}
