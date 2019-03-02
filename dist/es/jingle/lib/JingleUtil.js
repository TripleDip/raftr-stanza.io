export const SessionRole = {
    Initiator: 'initiator',
    Responder: 'responder'
};
export const ApplicationDirection = {
    Inactive: 'inactive',
    Receive: 'recvonly',
    Send: 'sendonly',
    SendReceive: 'sendrecv'
};
export const ContentSenders = {
    Both: 'both',
    Initiator: 'initiator',
    None: 'none',
    Responder: 'responder'
};
export function sendersToDirection(role, senders = 'both') {
    const isInitiator = role === SessionRole.Initiator;
    switch (senders) {
        case ContentSenders.Initiator:
            return isInitiator ? ApplicationDirection.Send : ApplicationDirection.Receive;
        case ContentSenders.Responder:
            return isInitiator ? ApplicationDirection.Receive : ApplicationDirection.Send;
        case ContentSenders.Both:
            return ApplicationDirection.SendReceive;
    }
    return ApplicationDirection.Inactive;
}
export function directionToSenders(role, direction = 'sendrecv') {
    const isInitiator = role === SessionRole.Initiator;
    switch (direction) {
        case ApplicationDirection.Send:
            return isInitiator ? ContentSenders.Initiator : ContentSenders.Responder;
        case ApplicationDirection.Receive:
            return isInitiator ? ContentSenders.Responder : ContentSenders.Initiator;
        case ApplicationDirection.SendReceive:
            return ContentSenders.Both;
    }
    return ContentSenders.None;
}
