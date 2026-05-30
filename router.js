import { UPSTREAMS, MIX_PROVIDER } from './config.js';

const VALID_PROVIDERS = new Set([...Object.keys(UPSTREAMS), MIX_PROVIDER]);

export function resolveRoute(request) {
  const url = new URL(request.url);
  const { pathname, search } = url;

  // ── ECH / 优选 IP 参数提取（用于 DNS 路径） ──────────
  const echParams = {
    cfDomain: url.searchParams.get('cf') || null,
    ip4: url.searchParams.get('ip4') || null,
    ip6: url.searchParams.get('ip6') || null,
    echDomain: url.searchParams.get('ech') || null,
  };

  // Homepage routes
  if (pathname === '/' || pathname === '/index.html' || pathname === '/en') {
    return { home: true };
  }

  if (pathname === '/health') {
    return { health: true };
  }

  // RFC 8484: bare /dns-query without a provider prefix → mix
  if (pathname === '/dns-query') {
    return { provider: MIX_PROVIDER, queryString: search, echParams };
  }

  // /<provider>/dns-query pattern
  const match = pathname.match(/^\/([^/]+)\/dns-query$/);
  if (!match) return { error: 'not_found' };

  const provider = match[1];
  if (!VALID_PROVIDERS.has(provider)) return { error: 'unknown_provider' };

  return {
    provider,
    queryString: search,
    echParams,
  };
}
