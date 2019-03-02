import { Namespaces } from '../protocol';
export default function (client) {
    client.disco.addFeature(Namespaces.REACH_0);
    client.disco.addFeature(Namespaces.PEP_NOTIFY(Namespaces.REACH_0));
    client.on('pubsub:event', function (msg) {
        if (!msg.event.updated) {
            return;
        }
        if (msg.event.updated.node !== Namespaces.REACH_0) {
            return;
        }
        client.emit('reachability', {
            addresses: msg.event.updated.published[0].reach,
            jid: msg.from
        });
    });
    client.on('presence', function (pres) {
        if (!pres.reach || !pres.reach.length) {
            return;
        }
        client.emit('reachability', {
            addresses: pres.reach,
            jid: pres.from
        });
    });
    client.publishReachability = function (data, cb) {
        return this.publish('', Namespaces.REACH_0, {
            reach: data
        }, cb);
    };
}
