/** DNS wire format utilities — response building, SERVFAIL, name parsing */

const DNS_HEADERS = { 'Content-Type': 'application/dns-message' };

export function dnsResponse(body, upstreamTime) {
  const headers = upstreamTime != null
    ? { ...DNS_HEADERS, 'X-Upstream-Time': String(upstreamTime) }
    : DNS_HEADERS;
  return new Response(body, { status: 200, headers });
}

export function buildDNS(id, qName, qType, rdataList, ttl) {
  const labels = qName.replace(/\.+$/, '').split('.');
  const nameBytes = [];
  for (const label of labels) {
    if (label.length > 63) break;
    nameBytes.push(label.length);
    for (let i = 0; i < label.length; i++) nameBytes.push(label.charCodeAt(i));
  }
  nameBytes.push(0);

  let totalLen = 12 + nameBytes.length + 4;
  for (const rd of rdataList) totalLen += 12 + rd.length;

  const buf = new ArrayBuffer(totalLen);
  const bytes = new Uint8Array(buf);
  const view = new DataView(buf);
  view.setUint16(0, id);
  view.setUint16(2, 0x8180);
  view.setUint16(4, 1);
  view.setUint16(6, rdataList.length);
  view.setUint16(8, 0);
  view.setUint16(10, 0);

  let offset = 12;
  bytes.set(nameBytes, offset); offset += nameBytes.length;
  view.setUint16(offset, qType); offset += 2;
  view.setUint16(offset, 1); offset += 2;

  for (const rd of rdataList) {
    view.setUint16(offset, 0xC00C); offset += 2;
    view.setUint16(offset, qType); offset += 2;
    view.setUint16(offset, 1); offset += 2;
    view.setUint32(offset, ttl); offset += 4;
    view.setUint16(offset, rd.length); offset += 2;
    bytes.set(rd, offset); offset += rd.length;
  }
  return buf;
}

export function servfail(originalBody, edeCode = 0, edeText = '') {
  const id = originalBody && originalBody.byteLength >= 2 ? new DataView(originalBody).getUint16(0) : 0;
  const textBytes = new TextEncoder().encode(edeText);
  const edeOptionLen = edeCode ? (6 + textBytes.length) : 0;

  const headerLen = 12;
  const qdEnd = skipQuestion(originalBody);
  const qdBytes = qdEnd > headerLen ? new Uint8Array(originalBody.slice(headerLen, qdEnd)) : new Uint8Array(0);

  const arcount = edeCode ? 1 : 0;
  const optLen = edeCode ? (11 + edeOptionLen) : 0;
  const total = headerLen + qdBytes.length + optLen;
  const buf = new ArrayBuffer(total);
  const out = new DataView(buf);
  const bytes = new Uint8Array(buf);

  const qdcount = qdBytes.length > 0 ? 1 : 0;
  out.setUint16(0, id);
  out.setUint16(2, 0x8182);
  out.setUint16(4, qdcount);
  out.setUint16(6, 0);
  out.setUint16(8, 0);
  out.setUint16(10, arcount);
  bytes.set(qdBytes, headerLen);

  if (edeCode) {
    const off = headerLen + qdBytes.length;
    bytes[off] = 0;
    out.setUint16(off + 1, 41);
    out.setUint16(off + 3, 4096);
    out.setUint32(off + 5, 0);
    out.setUint16(off + 9, edeOptionLen);
    out.setUint16(off + 11, 15);
    out.setUint16(off + 13, 2 + textBytes.length);
    out.setUint16(off + 15, edeCode);
    if (textBytes.length) bytes.set(textBytes, off + 17);
  }

  return buf;
}

function skipQuestion(body) {
  if (!body || body.byteLength < 12) return 12;
  let off = 12;
  const bytes = new Uint8Array(body);
  while (off < bytes.length) {
    const len = bytes[off];
    if (len === 0) return off + 1 + 4;
    if (len & 0xC0) return off + 2 + 4;
    off += 1 + len;
  }
  return 12;
}
