import * as tslib_1 from "tslib";
import fetch from 'cross-fetch';
import { Namespaces } from '../protocol';
function promiseAny(promises) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        try {
            const errors = yield Promise.all(promises.map(p => {
                return p.then(val => Promise.reject(val), err => Promise.resolve(err));
            }));
            return Promise.reject(errors);
        }
        catch (val) {
            return Promise.resolve(val);
        }
    });
}
export function getHostMeta(JXT, opts) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        if (typeof opts === 'string') {
            opts = { host: opts };
        }
        const config = Object.assign({ json: true, ssl: true, xrd: true }, opts);
        const scheme = config.ssl ? 'https://' : 'http://';
        return promiseAny([
            fetch(`${scheme}${config.host}/.well-known/host-meta.json`).then((res) => tslib_1.__awaiter(this, void 0, void 0, function* () {
                if (!res.ok) {
                    throw new Error('could-not-fetch-json');
                }
                return res.json();
            })),
            fetch(`${scheme}${config.host}/.well-known/host-meta`).then((res) => tslib_1.__awaiter(this, void 0, void 0, function* () {
                if (!res.ok) {
                    throw new Error('could-not-fetch-xml');
                }
                const data = yield res.text();
                return JXT.parse(data);
            }))
        ]);
    });
}
export default function (client, stanzas) {
    client.discoverBindings = function (server, cb) {
        getHostMeta(stanzas, server)
            .then(data => {
            const results = {
                bosh: [],
                websocket: []
            };
            const links = data.links || [];
            for (const link of links) {
                if (link.href && link.rel === Namespaces.ALT_CONNECTIONS_WEBSOCKET) {
                    results.websocket.push(link.href);
                }
                if (link.href && link.rel === Namespaces.ALT_CONNECTIONS_XBOSH) {
                    results.bosh.push(link.href);
                }
            }
            cb(null, results);
        })
            .catch(err => {
            cb(err, []);
        });
    };
}
