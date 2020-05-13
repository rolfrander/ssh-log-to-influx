/**
 * @typedef AuthMessageEntry
 * @property {String} username
 * @property {String} ip
 * @property {String} port
 */

/**
 * Parse an SSH auth failed from rsyslog to JSON object.
 * It extracts :
 *  - username
 *  - ip
 *  - port
 * @param {String} message Log message
 * @returns {AuthMessageEntry}
 */
const parseAuthFailedMessage = (message) => {
    const regex = /Failed password for( invalid user)? (?<username>[^ ]+) from (?<ip>[^ ]+) port (?<port>\d*)/;
    return regex.exec(message)?.groups;
}

/**
 * Parse pf-sense filterlog.
 * https://docs.netgate.com/pfsense/en/latest/monitoring/raw-filter-log-format.html
 */
const parseFilterlog = (message) => {
    const regex = /(?<ruleno>[0-9]*),(?<subruleno>[0-9]*),(?<anchor>[a-zA-Z0-9]*),(?<tracker>[0-9]*),(?<ifc>[a-zA-Z0-9.]*),(?<reason>[a-zA-Z0-9]*),(?<action>[a-z]*),(?<direction>[a-z]*),((4,(?<tos>[0-9a-fx]*),,(?<ttl>[0-9]*),(?<id>[0-9]*),(?<offset>[0-9]*),(?<flags>[0-9a-zA-Z]*))|(6,(?<class>[0-9]*),(?<flowlabel>[^,]*),(?<hoplimit>[0-9]*))),(?<proto>[0-9]*),(?<protocol>[a-z]*),(?<length>[0-9]*),(?<ip>[0-9a-f.:]*),(?<dstip>[0-9a-f.:]*),(((?<srcport>[0-9]*),(?<dstport>[0-9]*))|(?<icmptype>[0-9a-zA-Z]*))/;
    return regex.exec(message)?.groups;
}

export { parseAuthFailedMessage, parseFilterlog };
