import { UPSTREAMS, HARD_TIMEOUT_MS } from './config.js';

const DNS_HEADERS = { 'Content-Type': 'application/dns-message' };

function buildWireQuery(domain, type) {
  const id = Math.floor(Math.random() * 65536);
  const labels = domain.replace(/\.+$/, '').split('.');

  let nameLen = 0;
  for (const label of labels) nameLen += label.length + 1;
  nameLen += 1;

  const total = 12 + nameLen + 4;
  const buf = new ArrayBuffer(total);
  const v = new DataView(buf);
  const bytes = new Uint8Array(buf);

  v.setUint16(0, id);
  v.setUint16(2, 0x0100);
  v.setUint16(4, 1);
  v.setUint16(6, 0);
  v.setUint16(8, 0);
  v.setUint16(10, 0);

  let offset = 12;
  for (const label of labels) {
    bytes[offset++] = label.length;
    for (let i = 0; i < label.length; i++) bytes[offset++] = label.charCodeAt(i);
  }
  bytes[offset++] = 0;

  v.setUint16(offset, type); offset += 2;
  v.setUint16(offset, 1);    offset += 2;

  return buf;
}

export async function resolveDNSWire(domain, type) {
  const query = buildWireQuery(domain, type);
  const started = Date.now();
  const deadline = started + HARD_TIMEOUT_MS;

  const entries = Object.entries(UPSTREAMS);
  if (entries.length === 0) return null;

  const controllers = [];

  function abortAll() {
    for (const c of controllers) {
      try { c.abort(); } catch (_) {}
    }
  }

  const promises = entries.map(function ([_name, cfg]) {
    const ctrl = new AbortController();
    controllers.push(ctrl);
    return fetch(cfg.url, {
      method: 'POST',
      headers: DNS_HEADERS,
      body: query,
      signal: ctrl.signal,
    }).then(async function (res) {
      if (res.status !== 200) return null;
      const buf = await res.arrayBuffer();
      if (buf.byteLength < 12) return null;
      const ancount = new DataView(buf).getUint16(6);
      if (ancount === 0) return null;
      return buf;
    }).catch(function (_) {
      return null;
    });
  });

  const timeoutPromise = new Promise(function (resolve) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) { resolve(null); return; }
    setTimeout(function () { resolve(null); }, remaining);
  });

  const racers = [...promises, timeoutPromise];

  while (racers.length > 1) {
    const winner = await Promise.race(racers);
    if (winner !== null) {
      abortAll();
      return winner;
    }
    // Either an upstream or timeout resolved null
    if (Date.now() >= deadline) break;
    const remaining = deadline - Date.now();
    if (remaining <= 0) break;
    // Replace timeout with a new shorter one for retry
    const newTimeout = new Promise(function (resolve) {
      setTimeout(function () { resolve(null); }, Math.min(remaining, 50));
    });
    const idx = racers.indexOf(timeoutPromise);
    if (idx >= 0) racers[idx] = newTimeout;
    timeoutPromise = newTimeout;
  }

  abortAll();
  return null;
}

export function extractIPBytes(buf, type) {
  try {
    const answers = parseAnswers(buf, type);
    return answers.filter(function (a) {
      return a.type === type && (a.rdata.length === 4 || a.rdata.length === 16);
    }).map(function (a) { return a.rdata; });
  } catch (_) {
    return [];
  }
}

export function extractIPStrings(buf, type) {
  try {
    const answers = parseAnswers(buf, type);
    if (type === 1) {
      return answers.filter(function (a) {
        return a.type === 1 && a.rdata.length === 4;
      }).map(function (a) {
        return a.rdata[0] + '.' + a.rdata[1] + '.' + a.rdata[2] + '.' + a.rdata[3];
      });
    }
    if (type === 28) {
      return answers.filter(function (a) {
        return a.type === 28 && a.rdata.length === 16;
      }).map(function (a) {
        const p = [];
        for (let i = 0; i < 16; i += 2) {
          p.push(((a.rdata[i] << 8) | a.rdata[i + 1]).toString(16));
        }
        return p.join(':');
      });
    }
    return [];
  } catch (_) {
    return [];
  }
}

function parseAnswers(buf, expectedType) {
  const bytes = buf instanceof ArrayBuffer
    ? new Uint8Array(buf)
    : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  if (bytes.length < 12) return [];

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const qdcount = view.getUint16(4);
  const ancount = view.getUint16(6);

  let offset = 12;

  for (let i = 0; i < qdcount; i++) {
    offset = skipName(bytes, offset);
    offset += 4;
  }

  const answers = [];
  for (let i = 0; i < ancount; i++) {
    if (offset + 10 > bytes.length) break;
    const nameEnd = skipName(bytes, offset);
    const type = view.getUint16(nameEnd);
    const ttl = view.getUint32(nameEnd + 4);
    const rdlength = view.getUint16(nameEnd + 8);
    const rdataOffset = nameEnd + 10;

    if (rdataOffset + rdlength > bytes.length) break;

    if (type === expectedType) {
      answers.push({
        type: type,
        rdata: bytes.slice(rdataOffset, rdataOffset + rdlength),
        ttl: ttl,
      });
    }
    offset = rdataOffset + rdlength;
  }

  return answers;
}

function skipName(bytes, start) {
  let offset = start;
  let end = start;
  let jumped = false;
  let jumps = 0;

  while (jumps < 128) {
    if (offset >= bytes.length) return end || offset;
    const len = bytes[offset];

    if ((len & 0xC0) === 0xC0) {
      if (offset + 1 >= bytes.length) break;
      const pointer = ((len & 0x3F) << 8) | bytes[offset + 1];
      if (pointer >= bytes.length) break;
      if (!jumped) end = offset + 2;
      offset = pointer;
      jumped = true;
      jumps++;
      continue;
    }

    if ((len & 0xC0) !== 0) break;
    if (len === 0) return jumped ? end : offset + 1;

    offset += 1 + len;
    if (!jumped) end = offset;
  }

  return end || offset;
}
