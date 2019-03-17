'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
function default_1(client) {
    client.registerFeature('session', 1000, function(features, cb) {
        const self = this;
        if (features.session.optional || self.sessionStarted) {
            self.features.negotiated.session = true;
            return cb();
        }
        self.sendIq(
            {
                session: {},
                type: 'set'
            },
            function(err) {
                if (err) {
                    return cb('disconnect', 'session request failed');
                }
                self.features.negotiated.session = true;
                if (!self.sessionStarted) {
                    self.sessionStarted = true;
                    self.emit('session:started', self.jid);
                }
                cb();
            }
        );
    });
    client.on('disconnected', function() {
        client.sessionStarted = false;
        client.features.negotiated.session = false;
    });
}
exports.default = default_1;
