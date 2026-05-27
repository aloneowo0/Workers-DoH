/** Active DNS upstream endpoints. */
export const UPSTREAMS = {
    google: 'https://dns.google/dns-query',
    cloudflare: 'https://cloudflare-dns.com/dns-query',
    quad9:    'https://dns11.quad9.net/dns-query',
    adguard:  'https://dns.adguard-dns.com/dns-query',
    opendns:  'https://dns.opendns.com/dns-query',
};

/** Concurrency: hard cap on total wait (ms). */
export const HARD_TIMEOUT_MS = 800;

/** Mix priority when ECS is present (original or injected). */
export const ECS_PRIORITY = ['google', 'quad9', 'adguard', 'opendns', 'cloudflare'];

/** Mix priority when no ECS. */
export const NO_ECS_PRIORITY = ['cloudflare', 'google', 'quad9', 'adguard', 'opendns'];

/** EDNS client-subnet IPv4 prefix length. */
export const ECS_PREFIX4 = 24;

/** EDNS client-subnet IPv6 prefix length. */
export const ECS_PREFIX6 = 56;

/** A/AAAA answers matching these ranges are blocked. */
export const BLOCKED_RANGES = [
    { family: 4, addr: [127, 0, 0, 0], mask: 8 },            // loopback
    { family: 4, addr: [0, 0, 0, 0], mask: 32 },              // null
    { family: 6, mask: 128 },                                  // :: (unspecified)
    { family: 6, addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], mask: 128 }, // ::1
];

/** Recognized EDNS modes. */
export const EDNS_MODES = ['keep', 'auto', 'plus'];

/** Default EDNS mode when none is specified. */
export const DEFAULT_MODE = 'auto';

/** Upstream key that triggers concurrent-fetch behaviour. */
export const MIX_PROVIDER = 'mix';
