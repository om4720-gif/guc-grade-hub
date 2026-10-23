// Minimal NTLMv2 client (the GUC portal uses Windows/NTLM authentication).
import { createHmac } from "node:crypto";

const enc = new TextEncoder();

function utf16le(s: string): Uint8Array {
  const out = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    out[i * 2] = c & 0xff;
    out[i * 2 + 1] = c >> 8;
  }
  return out;
}

export function toB64(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
}
export function fromB64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const rotl = (x: number, s: number) => (x << s) | (x >>> (32 - s));

export function md4(msg: Uint8Array): Uint8Array {
  const len = msg.length;
  const n = ((len + 8) >> 6) + 1;
  const buf = new Uint8Array(n * 64);
  buf.set(msg);
  buf[len] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(n * 64 - 8, (len * 8) >>> 0, true);
  dv.setUint32(n * 64 - 4, Math.floor((len * 8) / 4294967296), true);

  let a0 = 0x67452301 | 0,
    b0 = 0xefcdab89 | 0,
    c0 = 0x98badcfe | 0,
    d0 = 0x10325476 | 0;
  const F = (x: number, y: number, z: number) => (x & y) | (~x & z);
  const G = (x: number, y: number, z: number) => (x & y) | (x & z) | (y & z);
  const H = (x: number, y: number, z: number) => x ^ y ^ z;
  const r3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];

  for (let blk = 0; blk < n; blk++) {
    const X: number[] = [];
    for (let i = 0; i < 16; i++) X.push(dv.getInt32(blk * 64 + i * 4, true));
    let a = a0,
      b = b0,
      c = c0,
      d = d0;
    for (let i = 0; i < 16; i++) {
      const t = rotl((a + F(b, c, d) + X[i]!) | 0, [3, 7, 11, 19][i % 4]!);
      [a, b, c, d] = [d, t, b, c];
    }
    for (let i = 0; i < 16; i++) {
      const k = (i % 4) * 4 + (i >> 2);
      const t = rotl((a + G(b, c, d) + X[k]! + 0x5a827999) | 0, [3, 5, 9, 13][i % 4]!);
      [a, b, c, d] = [d, t, b, c];
    }
    for (let i = 0; i < 16; i++) {
      const t = rotl((a + H(b, c, d) + X[r3[i]!]! + 0x6ed9eba1) | 0, [3, 9, 11, 15][i % 4]!);
      [a, b, c, d] = [d, t, b, c];
    }
    a0 = (a0 + a) | 0;
    b0 = (b0 + b) | 0;
    c0 = (c0 + c) | 0;
    d0 = (d0 + d) | 0;
  }
  const out = new Uint8Array(16);
  const odv = new DataView(out.buffer);
  [a0, b0, c0, d0].forEach((v, i) => odv.setInt32(i * 4, v, true));
  return out;
}

function hmacMd5(key: Uint8Array, data: Uint8Array): Uint8Array {
  return new Uint8Array(createHmac("md5", key).update(data).digest());
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

const SIG = enc.encode("NTLMSSP\0");

export function ntlmType1(): string {
  const b = new Uint8Array(32);
  const dv = new DataView(b.buffer);
  b.set(SIG, 0);
  dv.setUint32(8, 1, true);
  // UNICODE | OEM | REQUEST_TARGET | NTLM | ALWAYS_SIGN | EXTENDED_SESSIONSECURITY | 128
  dv.setUint32(12, 0x1 | 0x2 | 0x4 | 0x200 | 0x8000 | 0x80000 | 0x20000000, true);
  dv.setUint16(16, 0, true);
  dv.setUint16(18, 0, true);
  dv.setUint32(20, 32, true);
  dv.setUint16(24, 0, true);
  dv.setUint16(26, 0, true);
  dv.setUint32(28, 32, true);
  return toB64(b);
}

export function ntlmType3(
  type2B64: string,
  username: string,
  password: string,
  domain = "",
  workstation = "WEB",
): string {
  const t2 = fromB64(type2B64);
  const dv2 = new DataView(t2.buffer, t2.byteOffset, t2.byteLength);
  if (t2.length < 48 || dv2.getUint32(8, true) !== 2) throw new Error("Bad NTLM challenge");
  const flags = dv2.getUint32(20, true);
  const challenge = t2.slice(24, 32);
  const tiLen = dv2.getUint16(40, true);
  const tiOff = dv2.getUint32(44, true);
  const targetInfo = t2.slice(tiOff, tiOff + tiLen);

  const ntHash = md4(utf16le(password));
  const v2Hash = hmacMd5(ntHash, utf16le(username.toUpperCase() + domain));

  const clientNonce = crypto.getRandomValues(new Uint8Array(8));
  const ts = new Uint8Array(8);
  const tsDv = new DataView(ts.buffer);
  const filetime = (BigInt(Date.now()) + 11644473600000n) * 10000n;
  tsDv.setBigUint64(0, filetime, true);
  const blob = concat(
    new Uint8Array([1, 1, 0, 0, 0, 0, 0, 0]),
    ts,
    clientNonce,
    new Uint8Array(4),
    targetInfo,
    new Uint8Array(4),
  );
  const proof = hmacMd5(v2Hash, concat(challenge, blob));
  const ntResp = concat(proof, blob);
  const lmResp = new Uint8Array(24);

  const d = utf16le(domain);
  const u = utf16le(username);
  const w = utf16le(workstation);
  const base = 64;
  const offs = [base, 0, 0, 0, 0, 0];
  const fields = [lmResp, ntResp, d, u, w, new Uint8Array(0)];
  for (let i = 1; i < fields.length; i++) offs[i] = offs[i - 1]! + fields[i - 1]!.length;

  const head = new Uint8Array(base);
  const dv = new DataView(head.buffer);
  head.set(SIG, 0);
  dv.setUint32(8, 3, true);
  fields.forEach((f, i) => {
    dv.setUint16(12 + i * 8, f.length, true);
    dv.setUint16(14 + i * 8, f.length, true);
    dv.setUint32(16 + i * 8, offs[i]!, true);
  });
  const outFlags = (flags & ~(0x40000000 | 0x10 | 0x20)) >>> 0;
  dv.setUint32(60, outFlags, true);
  return toB64(concat(head, ...fields));
}
