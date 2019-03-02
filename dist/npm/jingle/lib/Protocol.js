"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const JingleUtil_1 = require("./JingleUtil");
function convertIntermediateToApplication(media, role) {
    const rtp = media.rtpParameters;
    const rtcp = media.rtcpParameters || {};
    const encodingParameters = media.rtpEncodingParameters || [];
    let hasSSRC = false;
    if (encodingParameters && encodingParameters.length) {
        hasSSRC = !!encodingParameters[0].ssrc; // !== false ???
    }
    const application = {
        applicationType: 'rtp',
        headerExtensions: [],
        media: media.kind,
        mux: rtcp.mux,
        payloads: [],
        reducedSize: rtcp.reducedSize,
        sourceGroups: [],
        sources: [],
        ssrc: hasSSRC ? encodingParameters[0].ssrc.toString() : undefined,
        streams: []
    };
    for (const ext of rtp.headerExtensions || []) {
        application.headerExtensions.push({
            id: ext.id,
            senders: ext.direction && ext.direction !== 'sendrecv'
                ? JingleUtil_1.directionToSenders(role, ext.direction)
                : undefined,
            uri: ext.uri
        });
    }
    if (rtcp.ssrc && rtcp.cname) {
        application.sources = [
            {
                parameters: [
                    {
                        key: 'cname',
                        value: rtcp.cname
                    }
                ],
                ssrc: rtcp.ssrc.toString()
            }
        ];
    }
    if (hasSSRC && encodingParameters[0] && encodingParameters[0].rtx) {
        application.sourceGroups = [
            {
                semantics: 'FID',
                sources: [
                    encodingParameters[0].ssrc.toString(),
                    encodingParameters[0].rtx.ssrc.toString()
                ]
            }
        ];
    }
    for (const stream of media.streams || []) {
        application.streams.push({
            id: stream.stream,
            track: stream.track
        });
    }
    for (const codec of rtp.codecs || []) {
        const payload = {
            channels: codec.channels.toString(),
            clockrate: codec.clockRate.toString(),
            feedback: [],
            id: codec.payloadType.toString(),
            maxptime: codec.maxptime ? codec.maxptime.toString() : undefined,
            name: codec.name,
            parameters: []
        };
        for (const key of Object.keys(codec.parameters || {})) {
            if (key === 'ptime') {
                payload.ptime = codec.parameters[key].toString();
                continue;
            }
            payload.parameters.push({
                key,
                value: codec.parameters[key]
            });
        }
        for (const feedback of codec.rtcpFeedback || []) {
            payload.feedback.push({
                subtype: feedback.parameter,
                type: feedback.type
            });
        }
        application.payloads.push(payload);
    }
    return application;
}
exports.convertIntermediateToApplication = convertIntermediateToApplication;
function convertIntermediateToCandidate(candidate) {
    return {
        component: candidate.component.toString(),
        foundation: candidate.foundation,
        generation: undefined,
        id: undefined,
        ip: candidate.ip,
        network: undefined,
        port: candidate.port.toString(),
        priority: candidate.priority.toString(),
        protocol: candidate.protocol,
        relAddr: candidate.relatedAddress,
        relPort: candidate.relatedPort ? candidate.relatedPort.toString() : undefined,
        tcpType: candidate.tcpType,
        type: candidate.type
    };
}
function convertIntermediateToTransport(media) {
    const ice = media.iceParameters;
    const dtls = media.dtlsParameters;
    const transport = {
        candidates: [],
        transportType: 'iceUdp'
    };
    if (ice) {
        transport.ufrag = ice.usernameFragment;
        transport.pwd = ice.password;
    }
    if (dtls) {
        transport.fingerprints = dtls.fingerprints.map(fingerprint => ({
            hash: fingerprint.algorithm,
            setup: media.setup,
            value: fingerprint.value
        }));
    }
    if (media.sctp) {
        transport.sctp = [media.sctp];
    }
    for (const candidate of media.candidates || []) {
        transport.candidates.push(convertIntermediateToCandidate(candidate));
    }
    return transport;
}
exports.convertIntermediateToTransport = convertIntermediateToTransport;
function convertIntermediateToRequest(session, role) {
    return {
        contents: session.media.map(media => {
            const isRTP = media.kind === 'audio' || media.kind === 'video';
            return {
                application: isRTP
                    ? convertIntermediateToApplication(media, role)
                    : {
                        applicationType: 'datachannel',
                        protocol: media.protocol
                    },
                creator: JingleUtil_1.SessionRole.Initiator,
                name: media.mid,
                senders: JingleUtil_1.directionToSenders(role, media.direction),
                transport: convertIntermediateToTransport(media)
            };
        }),
        groups: session.groups
            ? session.groups.map(group => ({
                contents: group.mids,
                semantics: group.semantics
            }))
            : undefined
    };
}
exports.convertIntermediateToRequest = convertIntermediateToRequest;
function convertContentToIntermediate(content, role) {
    const application = content.application || {};
    const transport = content.transport;
    const isRTP = application && application.applicationType === 'rtp';
    const media = {
        direction: JingleUtil_1.sendersToDirection(role, content.senders),
        kind: application.media || 'application',
        mid: content.name,
        protocol: isRTP ? 'UDP/TLS/RTP/SAVPF' : 'UDP/DTLS/SCTP'
    };
    if (isRTP) {
        media.rtcpParameters = {
            mux: application.mux,
            reducedSize: application.reducedSize
        };
        if (application.sources && application.sources.length) {
            const source = application.sources[0];
            media.rtcpParameters.ssrc = parseInt(source.ssrc, 10);
            if (source.parameters) {
                const cname = source.parameters.find(p => p.key === 'cname');
                media.rtcpParameters.cname = cname ? cname.value : undefined;
            }
        }
        media.rtpParameters = {
            codecs: [],
            fecMechanisms: [],
            headerExtensions: []
        };
        if (application.streams) {
            media.streams = [];
            for (const stream of application.streams) {
                media.streams.push({
                    stream: stream.id,
                    track: stream.track
                });
            }
        }
        if (application.ssrc) {
            media.rtpEncodingParameters = [
                {
                    ssrc: parseInt(application.ssrc, 10)
                }
            ];
            if (application.sourceGroups && application.sourceGroups.length) {
                const group = application.sourceGroups[0];
                media.rtpEncodingParameters[0].rtx = {
                    // TODO: actually look for a FID one with matching ssrc
                    ssrc: parseInt(group.sources[1], 10)
                };
            }
        }
        for (const payload of application.payloads || []) {
            const parameters = {};
            for (const param of payload.parameters || []) {
                parameters[param.key] = param.value;
            }
            const rtcpFeedback = [];
            for (const fb of payload.feedback || []) {
                rtcpFeedback.push({
                    parameter: fb.subtype,
                    type: fb.type
                });
            }
            media.rtpParameters.codecs.push({
                channels: parseInt(payload.channels, 10),
                clockRate: parseInt(payload.clockrate, 10),
                name: payload.name,
                numChannels: parseInt(payload.channels, 10),
                parameters,
                payloadType: parseInt(payload.id, 10),
                rtcpFeedback
            });
            for (const ext of application.headerExtensions || []) {
                media.rtpParameters.headerExtensions.push({
                    direction: ext.senders && ext.senders !== 'both'
                        ? JingleUtil_1.sendersToDirection(role, ext.senders)
                        : undefined,
                    id: ext.id,
                    uri: ext.uri
                });
            }
        }
    }
    if (transport) {
        if (transport.ufrag && transport.pwd) {
            media.iceParameters = {
                password: transport.pwd,
                usernameFragment: transport.ufrag
            };
        }
        if (transport.fingerprints && transport.fingerprints.length) {
            media.dtlsParameters = {
                fingerprints: [],
                role: 'auto'
            };
            for (const fingerprint of transport.fingerprints) {
                media.dtlsParameters.fingerprints.push({
                    algorithm: fingerprint.hash,
                    value: fingerprint.value
                });
            }
            if (transport.sctp) {
                media.sctp = transport.sctp[0];
            }
            media.setup = transport.fingerprints[0].setup;
        }
    }
    return media;
}
exports.convertContentToIntermediate = convertContentToIntermediate;
function convertRequestToIntermediate(jingle, role) {
    const session = {
        groups: [],
        media: []
    };
    for (const group of jingle.groups || []) {
        session.groups.push({
            mids: group.contents,
            semantics: group.semantics
        });
    }
    for (const content of jingle.contents || []) {
        session.media.push(convertContentToIntermediate(content, role));
    }
    return session;
}
exports.convertRequestToIntermediate = convertRequestToIntermediate;
function convertIntermediateToTransportInfo(mid, candidate) {
    return {
        contents: [
            {
                creator: JingleUtil_1.SessionRole.Initiator,
                name: mid,
                transport: {
                    candidates: [convertIntermediateToCandidate(candidate)],
                    transportType: 'iceUdp',
                    ufrag: candidate.usernameFragment || undefined
                }
            }
        ]
    };
}
exports.convertIntermediateToTransportInfo = convertIntermediateToTransportInfo;
