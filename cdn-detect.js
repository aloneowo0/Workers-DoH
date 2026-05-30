/**
 * CDN owner detection module for Workers-DoH v2.
 * Detects whether an IP or domain belongs to Cloudflare or Meta CDN
 * using compiled CIDR range matching.
 */

const RAW_META_CIDRS = [
    '31.13.24.0/21', '31.13.64.0/18', '45.64.40.0/22',
    '57.141.0.0/24', '57.144.0.0/14', '66.220.144.0/20',
    '69.63.176.0/20', '69.171.224.0/19', '74.119.76.0/22',
    '102.132.96.0/20', '103.4.96.0/22', '129.134.0.0/17',
    '157.240.0.0/17', '157.240.192.0/18', '163.70.128.0/17',
    '173.252.64.0/18', '179.60.192.0/22', '185.60.216.0/22',
    '185.89.216.0/22', '199.201.64.0/22', '204.15.20.0/22',
    '2620:0:1c00::/40', '2a03:2880::/32', '2a03:2887:ff00::/48',
    '2a03:2887:ff04::/46', '2a03:2887:ff20::/48', '2a03:2887:ff30::/48',
    '2a03:2887:ff40::/46', '2a03:2887:ff50::/45', '2a03:2887:ff64::/46',
    '2c0f:ef78:3::/48', '2c0f:ef78:5::/48', '2c0f:ef78:9::/48',
    '2c0f:ef78:c::/47', '2c0f:ef78:e::/48', '2c0f:ef78:10::/47',
];

const RAW_CF_CIDRS = [
    '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13',
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
    '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
    '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
    '198.41.128.0/17', '162.158.0.0/15',
    '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32',
    '2405:b500::/32', '2405:8100::/32', '2a06:98c0::/29',
    '2c0f:f248::/32',
];

const CACHE_TTL = 3600 * 1000;
const GOOGLE_DOH_JSON = 'https://dns.google/resolve';

const probeCache = new Map();

const COMPILED_META = compileCidrs(RAW_META_CIDRS);
const COMPILED_CF = compileCidrs(RAW_CF_CIDRS);

/**
 * Synchronously detect the CDN owner of an IP address.
 * @param {string} ip - IPv4 or IPv6 address
 * @returns {'CF'|'META'|null}
 */
export function detectOwner(ip) {
    try {
        if (!ip || typeof ip !== 'string') return null;
        const trimmed = ip.trim();
        if (!trimmed) return null;

        if (isIpInCompiled(trimmed, COMPILED_CF)) return 'CF';
        if (isIpInCompiled(trimmed, COMPILED_META)) return 'META';
        return null;
    } catch (_) {
        return null;
    }
}

/**
 * Asynchronously probe a domain's A records to determine its CDN owner.
 * Caches results in a module-level Map with 1-hour TTL.
 * @param {string} domain - Domain name to probe
 * @returns {Promise<{owner: 'CF'|'META'|null, ips: string[]}>}
 */
export async function probeOwner(domain) {
    try {
        if (!domain || typeof domain !== 'string') {
            return { owner: null, ips: [] };
        }

        const key = domain.trim().toLowerCase();
        if (!key) return { owner: null, ips: [] };

        const cached = probeCache.get(key);
        if (cached && cached.expire > Date.now()) {
            return { owner: cached.owner, ips: cached.ips };
        }

        const ips = await resolveA(key);
        let owner = null;
        for (const ip of ips) {
            if (isIpInCompiled(ip, COMPILED_CF)) { owner = 'CF'; break; }
            if (isIpInCompiled(ip, COMPILED_META)) { owner = 'META'; break; }
        }

        probeCache.set(key, { owner, ips, expire: Date.now() + CACHE_TTL });
        return { owner, ips };
    } catch (_) {
        return { owner: null, ips: [] };
    }
}

async function resolveA(domain) {
    try {
        const url = `${GOOGLE_DOH_JSON}?name=${encodeURIComponent(domain)}&type=1`;
        const res = await fetch(url, { headers: { 'Accept': 'application/dns-json' } });
        if (!res.ok) return [];
        const data = await res.json();
        if (data.Answer) {
            return data.Answer
                .filter(function (a) { return a.type === 1 && a.data; })
                .map(function (a) { return a.data; });
        }
        return [];
    } catch (_) {
        return [];
    }
}

function compileCidrs(cidrList) {
    const v4 = [];
    const v6 = [];
    for (let i = 0; i < cidrList.length; i++) {
        try {
            const cidr = cidrList[i];
            const parts = cidr.split('/');
            if (parts.length !== 2) continue;
            const ip = parts[0];
            const bits = parseInt(parts[1], 10);
            if (isNaN(bits)) continue;

            if (ip.includes(':')) {
                const mask = ~((1n << (128n - BigInt(bits))) - 1n);
                const ipBn = ipv6ToBigInt(ip);
                const start = ipBn & mask;
                const end = start | ((1n << (128n - BigInt(bits))) - 1n);
                v6.push({ start: start, end: end });
            } else {
                const mask = ~((1 << (32 - bits)) - 1);
                const ipNum = ipToLong(ip);
                const start = (ipNum & mask) >>> 0;
                const end = (start | ((1 << (32 - bits)) - 1)) >>> 0;
                v4.push({ start: start, end: end });
            }
        } catch (_) {}
    }
    return { v4: v4, v6: v6 };
}

function isIpInCompiled(ip, compiled) {
    if (ip.includes(':')) {
        try {
            const ipBn = ipv6ToBigInt(ip);
            const ranges = compiled.v6;
            for (let i = 0; i < ranges.length; i++) {
                if (ipBn >= ranges[i].start && ipBn <= ranges[i].end) return true;
            }
        } catch (_) {}
    } else {
        try {
            const ipNum = ipToLong(ip);
            const ranges = compiled.v4;
            for (let i = 0; i < ranges.length; i++) {
                if (ipNum >= ranges[i].start && ipNum <= ranges[i].end) return true;
            }
        } catch (_) {}
    }
    return false;
}

function ipToLong(ip) {
    const parts = ip.split('.');
    if (parts.length !== 4) throw new Error('bad IPv4');
    let result = 0;
    for (let i = 0; i < 4; i++) {
        const n = parseInt(parts[i], 10);
        if (isNaN(n) || n < 0 || n > 255) throw new Error('bad IPv4 octet');
        result = (result << 8) + n;
    }
    return result >>> 0;
}

function ipv6ToBigInt(ip) {
    let groups = ip.split(':');
    if (ip.includes('::')) {
        const doubleColon = ip.indexOf('::');
        const left = ip.substring(0, doubleColon);
        const right = ip.substring(doubleColon + 2);
        const leftParts = left ? left.split(':') : [];
        const rightParts = right ? right.split(':') : [];
        const fill = 8 - leftParts.length - rightParts.length;
        if (fill < 0) throw new Error('bad IPv6');
        groups = [];
        for (let i = 0; i < leftParts.length; i++) groups.push(leftParts[i]);
        for (let i = 0; i < fill; i++) groups.push('0');
        for (let i = 0; i < rightParts.length; i++) groups.push(rightParts[i]);
    }
    if (groups.length !== 8) throw new Error('bad IPv6 group count');

    let result = 0n;
    for (let i = 0; i < 8; i++) {
        const val = parseInt(groups[i] || '0', 16);
        if (isNaN(val) || val > 0xFFFF || val < 0) throw new Error('bad IPv6 group');
        result = (result << 16n) + BigInt(val);
    }
    return result;
}
