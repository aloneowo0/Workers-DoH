/** Special domain handling — remap, CDN owner detection, CIDR matching */

import { toBytes, encodeDnsName, buildDNS, resolveDNSWire, extractIPBytes, extractIPStrings } from './dns-lib.js';

const TYPE_A = 1;
const TYPE_AAAA = 28;
const TYPE_HTTPS = 65;
const CACHE_TTL = 300_000;
const PROBE_CACHE_TTL = 3600 * 1000;

// AS32934 scanned 2026-05-31 — only REACHABLE IPv4 + IPv6
const RAW_META_CIDRS = [
    '31.13.64.0/18',
    '31.13.64.0/24',
    '31.13.69.0/24',
    '31.13.70.0/24',
    '31.13.71.0/24',
    '31.13.82.0/24',
    '31.13.87.0/24',
    '31.13.89.0/24',
    '31.13.91.0/24',
    '31.13.93.0/24',
    '31.13.94.0/24',
    '31.13.95.0/24',
    '57.144.14.0/23',
    '57.144.22.0/23',
    '57.144.38.0/23',
    '57.144.42.0/23',
    '57.144.44.0/23',
    '57.144.50.0/23',
    '57.144.54.0/23',
    '57.144.56.0/23',
    '57.144.64.0/23',
    '57.144.66.0/23',
    '57.144.68.0/23',
    '57.144.70.0/23',
    '57.144.72.0/23',
    '57.144.74.0/23',
    '57.144.76.0/23',
    '57.144.78.0/23',
    '57.144.80.0/23',
    '57.144.84.0/23',
    '57.144.86.0/23',
    '57.144.100.0/23',
    '57.144.104.0/23',
    '57.144.108.0/23',
    '57.144.110.0/23',
    '57.144.112.0/23',
    '57.144.114.0/23',
    '57.144.120.0/23',
    '57.144.124.0/23',
    '57.144.126.0/23',
    '57.144.128.0/23',
    '57.144.132.0/23',
    '57.144.134.0/23',
    '57.144.136.0/23',
    '57.144.138.0/23',
    '57.144.140.0/23',
    '57.144.142.0/23',
    '57.144.144.0/23',
    '57.144.148.0/23',
    '57.144.150.0/23',
    '57.144.152.0/23',
    '57.144.160.0/23',
    '57.144.162.0/23',
    '57.144.164.0/23',
    '57.144.172.0/23',
    '57.144.174.0/23',
    '57.144.176.0/23',
    '57.144.178.0/23',
    '57.144.180.0/23',
    '57.144.182.0/23',
    '57.144.184.0/23',
    '57.144.186.0/23',
    '57.144.188.0/23',
    '57.144.192.0/23',
    '57.144.194.0/23',
    '57.144.196.0/23',
    '57.144.198.0/23',
    '57.144.200.0/23',
    '57.144.202.0/23',
    '57.144.204.0/23',
    '57.144.206.0/23',
    '57.144.208.0/23',
    '57.144.210.0/23',
    '57.144.212.0/23',
    '57.144.216.0/23',
    '57.144.218.0/23',
    '57.144.220.0/23',
    '57.144.222.0/23',
    '57.144.228.0/23',
    '57.144.232.0/23',
    '57.144.234.0/23',
    '57.144.236.0/23',
    '57.144.238.0/23',
    '57.144.240.0/23',
    '57.144.242.0/23',
    '57.144.244.0/23',
    '57.144.246.0/23',
    '57.144.248.0/23',
    '57.144.250.0/23',
    '57.144.252.0/23',
    '57.144.254.0/23',
    '57.145.0.0/23',
    '57.145.2.0/23',
    '57.145.4.0/23',
    '57.145.6.0/23',
    '57.145.8.0/23',
    '57.145.12.0/23',
    '102.132.99.0/24',
    '102.132.104.0/24',
    '157.240.0.0/17',
    '157.240.0.0/24',
    '157.240.3.0/24',
    '157.240.5.0/24',
    '157.240.8.0/24',
    '157.240.9.0/24',
    '157.240.11.0/24',
    '157.240.12.0/24',
    '157.240.13.0/24',
    '157.240.14.0/24',
    '157.240.15.0/24',
    '157.240.17.0/24',
    '157.240.22.0/24',
    '157.240.24.0/24',
    '157.240.25.0/24',
    '157.240.26.0/24',
    '157.240.27.0/24',
    '157.240.29.0/24',
    '157.240.30.0/24',
    '157.240.31.0/24',
    '157.240.196.0/24',
    '157.240.197.0/24',
    '157.240.200.0/24',
    '157.240.202.0/24',
    '157.240.203.0/24',
    '157.240.205.0/24',
    '157.240.208.0/24',
    '157.240.209.0/24',
    '157.240.210.0/24',
    '157.240.211.0/24',
    '157.240.212.0/24',
    '157.240.214.0/24',
    '157.240.223.0/24',
    '157.240.224.0/24',
    '157.240.225.0/24',
    '157.240.226.0/24',
    '157.240.227.0/24',
    '157.240.231.0/24',
    '157.240.233.0/24',
    '157.240.234.0/24',
    '157.240.238.0/24',
    '157.240.241.0/24',
    '157.240.243.0/24',
    '157.240.244.0/24',
    '157.240.253.0/24',
    '157.240.254.0/24',
    '163.70.128.0/17',
    '163.70.128.0/24',
    '163.70.131.0/24',
    '163.70.144.0/24',
    '163.70.151.0/24',
    '163.70.159.0/24',
    '163.77.132.0/23',
    '163.77.132.0/24',
    '163.77.133.0/24',
    '163.77.136.0/23',
    '163.77.136.0/24',
    '163.77.137.0/24',
    '185.60.217.0/24',
    '185.60.218.0/24',
    '185.60.219.0/24',
    '2620:0:1c00::/40',
    '2620:10d:c090::/44',
    '2a03:2880::/32',
    '2a03:2887:ff00::/48',
    '2a03:2887:ff02::/48',
    '2a03:2887:ff04::/46',
    '2a03:2887:ff09::/48',
    '2a03:2887:ff0a::/48',
    '2a03:2887:ff1b::/48',
    '2a03:2887:ff1c::/48',
    '2a03:2887:ff1e::/48',
    '2a03:2887:ff20::/48',
    '2a03:2887:ff22::/47',
    '2a03:2887:ff27::/48',
    '2a03:2887:ff28::/46',
    '2a03:2887:ff2f::/48',
    '2a03:2887:ff30::/48',
    '2a03:2887:ff33::/48',
    '2a03:2887:ff37::/48',
    '2a03:2887:ff38::/46',
    '2a03:2887:ff3f::/48',
    '2a03:2887:ff40::/46',
    '2a03:2887:ff44::/47',
    '2a03:2887:ff48::/46',
    '2a03:2887:ff4d::/48',
    '2a03:2887:ff4e::/47',
    '2a03:2887:ff50::/45',
    '2a03:2887:ff58::/47',
    '2a03:2887:ff5a::/48',
    '2a03:2887:ff5f::/48',
    '2a03:2887:ff60::/48',
    '2a03:2887:ff62::/47',
    '2a03:2887:ff64::/46',
    '2a03:2887:ff68::/47',
    '2a03:2887:ff6a::/48',
    '2a03:2887:ff70::/47',
    '2c0f:ef78:3::/48',
    '2c0f:ef78:5::/48',
    '2c0f:ef78:9::/48',
    '2c0f:ef78:c::/47',
    '2c0f:ef78:e::/48',
    '2c0f:ef78:10::/47',
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

const ipCache = new Map();
const probeCache = new Map();

const COMPILED_META = compileCidrs(RAW_META_CIDRS);
const COMPILED_CF = compileCidrs(RAW_CF_CIDRS);

export async function remapResponse(originalBody, queryName, queryType, preferredDomain, echRdata) {
    try {
        const id = parseQueryId(originalBody);

        if (queryType === TYPE_AAAA) {
            return buildDNS(id, queryName, TYPE_AAAA, [], 3600);
        }

        if (queryType === TYPE_HTTPS) {
            if (echRdata && echRdata.length > 0) {
                return buildDNS(id, queryName, TYPE_HTTPS, [echRdata], 3600);
            }
            return buildDNS(id, queryName, TYPE_HTTPS, [], 60);
        }

        if (queryType === TYPE_A) {
            if (!preferredDomain) return null;
            const ips = await resolvePreferredIPs(preferredDomain, TYPE_A);
            if (!ips || ips.length === 0) return null;
            return buildDNS(id, queryName, TYPE_A, ips, 60);
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

        const buf = await resolveDNSWire(domain, type);
        if (!buf) return null;

        const ips = extractIPBytes(buf, type);
        if (ips.length > 0) {
            ipCache.set(cacheKey, { ips, expires: Date.now() + CACHE_TTL });
            return ips;
        }

        return null;
    } catch (_) {
        return null;
    }
}

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

        probeCache.set(key, { owner, ips, expire: Date.now() + PROBE_CACHE_TTL });
        return { owner, ips };
    } catch (_) {
        return { owner: null, ips: [] };
    }
}

export function extractIps(buffer) {
  const ips = [];
  try {
    const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    if (bytes.length < 12) return ips;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const ancount = view.getUint16(6);
    let offset = 12;
    for (let i = 0; i < view.getUint16(4); i++) {
      while (offset < bytes.length) {
        const b = bytes[offset];
        if (b === 0) { offset++; break; }
        if ((b & 0xC0) === 0xC0) { offset += 2; break; }
        offset += b + 1;
      }
      offset += 4;
    }
    for (let i = 0; i < ancount; i++) {
      if (offset + 12 > bytes.length) break;
      let b = bytes[offset];
      if ((b & 0xC0) === 0xC0) { offset += 2; }
      else {
        while (b !== 0) {
          if ((b & 0xC0) === 0xC0) { offset += 1; break; }
          offset += b + 1;
          b = bytes[offset];
        }
        offset++;
      }
      const type = view.getUint16(offset); offset += 8;
      const rdlen = view.getUint16(offset); offset += 2;
      if (type === 1 && rdlen === 4) {
        ips.push(bytes[offset] + '.' + bytes[offset+1] + '.' + bytes[offset+2] + '.' + bytes[offset+3]);
      } else if (type === 28 && rdlen === 16) {
        const p = [];
        for (let j = 0; j < 16; j += 2) p.push(((bytes[offset+j] << 8) | bytes[offset+j+1]).toString(16));
        ips.push(p.join(':'));
      }
      offset += rdlen;
    }
  } catch (_) {}
  return ips;
}

export function isMetaDomain(name) {
  const domains = ['facebook.com','fbcdn.net','instagram.com','cdninstagram.com','messenger.com','whatsapp.com','whatsapp.net','threads.net','meta.com','oculus.com','fbsbx.com','thefacebook.com','connect.facebook.net'];
  try {
    return domains.some(function (d) { return name === d || name.endsWith('.' + d); });
  } catch (_) { return false; }
}

async function resolveA(domain) {
    try {
        const buf = await resolveDNSWire(domain, 1);
        if (!buf) return [];
        return extractIPStrings(buf, 1);
    } catch (_) {
        return [];
    }
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


