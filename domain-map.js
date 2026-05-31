/**
 * Domain resolution mapping module for Workers-DoH v2.
 *
 * Handles Twitter/X domain remapping:
 *   - A records: resolve preferred-domain IPs, return synthetic response
 *   - AAAA records: return empty (X doesn't support IPv6)
 *   - HTTPS records: inject CF ECH (when provided)
 *
 * To override remap domains, add this to config.js:
 *   export const TWITTER_DOMAINS = ["twimg.com", "twitter.com", "x.com", "t.co"];
 */

const TYPE_A = 1;
const TYPE_AAAA = 28;
const TYPE_HTTPS = 65;
const CACHE_TTL = 300_000;

const GOOGLE_DOH_JSON = 'https://dns.google/resolve';
const ipCache = new Map();

export async function remapResponse(originalBody, queryName, queryType, preferredDomain, echRdata) {
    try {
        const id = parseQueryId(originalBody);

        if (queryType === TYPE_AAAA) {
            return createDNSResponse(id, queryName, TYPE_AAAA, [], 3600);
        }

        if (queryType === TYPE_HTTPS) {
            if (echRdata && echRdata.length > 0) {
                return createDNSResponse(id, queryName, TYPE_HTTPS, [echRdata], 3600);
            }
            return createDNSResponse(id, queryName, TYPE_HTTPS, [], 60);
        }

        if (queryType === TYPE_A) {
            if (!preferredDomain) return null;
            const ips = await resolvePreferredIPs(preferredDomain, TYPE_A);
            if (!ips || ips.length === 0) return null;
            return createDNSResponse(id, queryName, TYPE_A, ips, 60);
        }

        return null;
    } catch (_) {
        return null;
    }
}

/**
 * Resolve a domain's A (type=1) or AAAA (type=28) records via Google DoH JSON API.
 * Returns an array of IP bytes (Uint8Array[]) or null on failure.
 * Results are cached for 300 seconds.
 */
export async function resolvePreferredIPs(domain, type) {
    try {
        const cacheKey = `${domain}|${type}`;
        const cached = ipCache.get(cacheKey);
        if (cached && Date.now() < cached.expires) {
            return cached.ips;
        }

        const url = `${GOOGLE_DOH_JSON}?name=${encodeURIComponent(domain)}&type=${type}`;
        const res = await fetch(url, { headers: { 'Accept': 'application/dns-json' } });
        if (!res.ok) return null;

        const data = await res.json();
        if (!data.Answer) return null;

        const ips = [];
        for (const a of data.Answer) {
            if (a.type === type) {
                if (type === TYPE_A) {
                    ips.push(ipToBytes(a.data));
                } else if (type === TYPE_AAAA) {
                    ips.push(ipv6ToBytes(a.data));
                }
            }
        }

        if (ips.length > 0) {
            ipCache.set(cacheKey, { ips, expires: Date.now() + CACHE_TTL });
            return ips;
        }

        return null;
    } catch (_) {
        return null;
    }
}

function createDNSResponse(id, qName, qType, rdataList, ttl) {
    const encodedName = encodeDnsName(qName);

    let totalLen = 12 + encodedName.length + 4;
    for (let i = 0; i < rdataList.length; i++) {
        totalLen += 12 + rdataList[i].length;
    }

    const buf = new Uint8Array(totalLen);
    const v = new DataView(buf.buffer);

    v.setUint16(0, id);                        // Transaction ID
    v.setUint16(2, 0x8180);                    // Flags: QR=1, RD=1, RA=1
    v.setUint16(4, 1);                         // QDCOUNT
    v.setUint16(6, rdataList.length);          // ANCOUNT
    v.setUint16(8, 0);                         // NSCOUNT
    v.setUint16(10, 0);                        // ARCOUNT

    let offset = 12;
    buf.set(encodedName, offset);
    offset += encodedName.length;
    v.setUint16(offset, qType);
    offset += 2;
    v.setUint16(offset, 1);                    // Class IN
    offset += 2;

    for (let i = 0; i < rdataList.length; i++) {
        const r = rdataList[i];
        v.setUint16(offset, 0xC00C);           // Name pointer to question (offset 12)
        offset += 2;
        v.setUint16(offset, qType);
        offset += 2;
        v.setUint16(offset, 1);                // Class IN
        offset += 2;
        v.setUint32(offset, ttl || 3600);
        offset += 4;
        v.setUint16(offset, r.length);         // RDLENGTH
        offset += 2;
        buf.set(r, offset);
        offset += r.length;
    }

    return buf.buffer;
}

function encodeDnsName(domain) {
    const parts = domain.split('.');
    const buf = new Uint8Array(domain.length + 2);
    let offset = 0;
    for (let i = 0; i < parts.length; i++) {
        const part = parts[i];
        buf[offset++] = part.length;
        for (let j = 0; j < part.length; j++) {
            buf[offset++] = part.charCodeAt(j);
        }
    }
    buf[offset++] = 0;
    return buf.slice(0, offset);
}

function parseQueryId(body) {
    try {
        const bytes = toBytes(body);
        if (bytes.length < 2) return 0;
        return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(0);
    } catch (_) {
        return 0;
    }
}

function ipToBytes(ip) {
    return new Uint8Array(ip.split('.').map(Number));
}

function ipv6ToBytes(ip) {
    let parts = ip.split(':');
    if (ip.includes('::')) {
        const [left, right] = ip.split('::');
        const leftParts = left ? left.split(':') : [];
        const rightParts = right ? right.split(':') : [];
        parts = [...leftParts, ...Array(8 - leftParts.length - rightParts.length).fill('0'), ...rightParts];
    }
    const buf = new Uint8Array(16);
    for (let i = 0; i < parts.length; i++) {
        const val = parseInt(parts[i], 16) || 0;
        buf[i * 2] = val >> 8;
        buf[i * 2 + 1] = val & 0xFF;
    }
    return buf;
}

function toBytes(body) {
    if (body instanceof ArrayBuffer) return new Uint8Array(body);
    if (ArrayBuffer.isView(body)) return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
    throw new Error('body must be ArrayBuffer or ArrayBufferView');
}
