#!/usr/bin/env node
// aee-verify.mjs — a verifier for the in-toto predicate
// "Adversarial Execution Evidence", type .../adversarial-execution-evidence/v0.7.
//
// Built from the specification text (agent-evidence-vectors v0.12.1,
// spec/predicates/adversarial-execution-evidence.md, SHA-256 759d2383e5da36fa...),
// without opening the conformance vectors, their changelog, or any other verifier.
// What was read, what was seen earlier, and every reading taken where the text
// left one open are listed in README.md.
//
// USAGE : node aee-verify.mjs [--explain] <statement.json>
//   exit 0 = the statement is valid      (verdict "accept")
//   exit 1 = the statement is invalid    (verdict "reject")
//   exit 2 = nothing was judged          (usage or I/O error, or an internal error of the verifier)
//   stdout is one line, one JSON object:
//     {"verdict":..,"codes":[..],"result":..,"tiers":[..]}   plus "primaryCode" on a refusal
//   --explain adds, on stderr, one line per finding (which row, which record).
//   Consumer key policy: environment variable AEE_SUBSTRATE_KEYS, a path to
//     {"substrateObservationKeys":[{"keyid":"..","publicKeyHex":".."}]}
//   Without it every `basis: substrate` row derives `unattested` (no trust on first use).
//
// No dependency: the Node.js standard library only.

import { readFileSync } from 'node:fs';
import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { realpathSync } from 'node:fs';

export const PREDICATE_TYPE = 'https://in-toto.io/attestation/adversarial-execution-evidence/v0.7';
export const STATEMENT_TYPE = 'https://in-toto.io/Statement/v1';
export const BINDING_VERSION = '2';
export const MAX_DEPTH = 128;

const POSTURES = new Set(['allowlist', 'no_network', 'sinkhole', 'unsafe_bypass_egress']);
const RESULT_ORDER = ['fail', 'degraded', 'pass_indirect', 'pass'];
const BASIS = new Set(['substrate', 'artifact']);
const METHOD = new Set(['intercepted', 'reconstructed']);
const ATTRIBUTION = new Set(['pinned', 'paired']);
const COVERING_KINDS = new Set(['interception', 'arming', 'sealed', 'examination']);
const NON_COVERING_KINDS = new Set(['moat-drop', 'uncommitted-observation']);
const CHAIN_TOKENS = new Set(['subject', 'corpus', 'networkPosture']);
// Every `aee*` member this version of the document defines, on any kind.
const KNOWN_AEE = new Set([
  'aeeRunBinding', 'aeeKind', 'aeeMethod', 'aeePayloadCommitment', 'aeePostureDigest',
  'aeeAssessedAttacks', 'aeeBindingVersion', 'aeeRunSeq', 'aeePrevRunBinding', 'aeeChainScope',
  'aeeStillArmed', 'aeeDropCount', 'aeeDropBound', 'aeeObservedSet', 'aeeObservedAttacks',
]);

// ───────────────────────── strict I-JSON parser, over raw bytes ─────────────────────────

export class JsonErr extends Error {
  constructor(code, msg, at) { super(msg); this.code = code; this.at = at; }
}
// A JSON number: its double value, and whether its token was written as an integer.
export class JNum {
  constructor(v, int) { this.v = v; this.int = int; }
}

function validateUtf8(buf) {
  const n = buf.length;
  let i = 0;
  const bad = (m) => { throw new JsonErr('JSON_INVALID_UTF8', m, i); };
  while (i < n) {
    const b = buf[i];
    if (b < 0x80) { i++; continue; }
    let need; let min1 = 0x80; let max1 = 0xBF;
    if (b >= 0xC2 && b <= 0xDF) need = 1;
    else if (b === 0xE0) { need = 2; min1 = 0xA0; }
    else if (b >= 0xE1 && b <= 0xEC) need = 2;
    else if (b === 0xED) { need = 2; max1 = 0x9F; }      // excludes UTF-8-encoded surrogates
    else if (b === 0xEE || b === 0xEF) need = 2;
    else if (b === 0xF0) { need = 3; min1 = 0x90; }
    else if (b >= 0xF1 && b <= 0xF3) need = 3;
    else if (b === 0xF4) { need = 3; max1 = 0x8F; }
    else bad('byte that cannot start a UTF-8 sequence (overlong forms included)');
    if (i + need >= n) bad('truncated UTF-8 sequence');
    const b1 = buf[i + 1];
    if (b1 < min1 || b1 > max1) bad('ill-formed UTF-8 sequence (overlong, surrogate or out of range)');
    for (let k = 2; k <= need; k++) {
      const bk = buf[i + k];
      if (bk < 0x80 || bk > 0xBF) bad('ill-formed UTF-8 continuation byte');
    }
    i += need + 1;
  }
}

function utf8At(buf, i) { // input already validated
  const b = buf[i];
  if (b < 0xE0) return [((b & 0x1F) << 6) | (buf[i + 1] & 0x3F), 2];
  if (b < 0xF0) return [((b & 0x0F) << 12) | ((buf[i + 1] & 0x3F) << 6) | (buf[i + 2] & 0x3F), 3];
  return [((b & 0x07) << 18) | ((buf[i + 1] & 0x3F) << 12) | ((buf[i + 2] & 0x3F) << 6) | (buf[i + 3] & 0x3F), 4];
}

const isNonchar = (cp) => (cp >= 0xFDD0 && cp <= 0xFDEF) || ((cp & 0xFFFE) === 0xFFFE);
const isDigit = (b) => b >= 0x30 && b <= 0x39;
const isHexByte = (b) => (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x46) || (b >= 0x61 && b <= 0x66);

// Parses one JSON text. Objects become Map (no prototype surprises, order kept), arrays Array,
// numbers JNum, strings JS strings. Throws JsonErr on anything outside the strict profile.
export function parseStrict(buf) {
  validateUtf8(buf);
  const n = buf.length;
  let i = 0;
  let depth = 0;
  const fail = (code, msg) => { throw new JsonErr(code, msg, i); };
  const ws = () => {
    while (i < n) {
      const b = buf[i];
      if (b === 0x20 || b === 0x09 || b === 0x0A || b === 0x0D) i++; else break;
    }
  };
  const lit = (w) => {
    if (i + w.length <= n && buf.toString('latin1', i, i + w.length) === w) { i += w.length; return true; }
    return false;
  };
  const hex4 = () => {
    if (i + 4 > n) fail('JSON_SYNTAX', 'truncated \\u escape');
    for (let k = 0; k < 4; k++) if (!isHexByte(buf[i + k])) fail('JSON_SYNTAX', '\\u escape is not exactly four hexadecimal digits');
    const v = parseInt(buf.toString('latin1', i, i + 4), 16);
    i += 4;
    return v;
  };
  function string() {
    i++; // opening quote
    const parts = [];
    let run = i; // start of the pending run of unescaped bytes, decoded in one piece
    const flush = () => { if (i > run) parts.push(buf.toString('utf8', run, i)); };
    for (;;) {
      if (i >= n) fail('JSON_SYNTAX', 'unterminated string');
      const b = buf[i];
      if (b === 0x22) { flush(); i++; break; }
      if (b === 0x5C) {
        flush();
        i++;
        if (i >= n) fail('JSON_SYNTAX', 'unterminated escape');
        const c = buf[i++];
        if (c === 0x22) parts.push('"');
        else if (c === 0x5C) parts.push('\\');
        else if (c === 0x2F) parts.push('/');
        else if (c === 0x62) parts.push('\b');
        else if (c === 0x66) parts.push('\f');
        else if (c === 0x6E) parts.push('\n');
        else if (c === 0x72) parts.push('\r');
        else if (c === 0x74) parts.push('\t');
        else if (c === 0x75) {
          const cu = hex4();
          let cp = cu;
          if (cu >= 0xD800 && cu <= 0xDBFF) {
            if (!(i + 1 < n && buf[i] === 0x5C && buf[i + 1] === 0x75)) fail('JSON_STRING_ILL_FORMED', 'high surrogate escape not followed by a low surrogate escape');
            i += 2;
            const lo = hex4();
            if (lo < 0xDC00 || lo > 0xDFFF) fail('JSON_STRING_ILL_FORMED', 'high surrogate escape not followed by a low surrogate escape');
            cp = 0x10000 + ((cu - 0xD800) << 10) + (lo - 0xDC00);
          } else if (cu >= 0xDC00 && cu <= 0xDFFF) {
            fail('JSON_STRING_ILL_FORMED', 'unpaired low surrogate escape');
          }
          if (isNonchar(cp)) fail('JSON_NONCHARACTER', 'Unicode noncharacter in a string');
          parts.push(String.fromCodePoint(cp));
        } else fail('JSON_SYNTAX', 'unknown escape');
        run = i;
        continue;
      }
      if (b < 0x20) fail('JSON_STRING_ILL_FORMED', 'raw control character in a string');
      if (b < 0x80) { i++; continue; }
      const [cp, len] = utf8At(buf, i);
      if (isNonchar(cp)) fail('JSON_NONCHARACTER', 'Unicode noncharacter in a string');
      i += len;
    }
    return parts.length === 1 ? parts[0] : parts.join('');
  }
  function number() {
    const start = i;
    if (buf[i] === 0x2D) i++;
    if (i >= n) fail('JSON_SYNTAX', 'truncated number');
    if (buf[i] === 0x30) i++;
    else if (buf[i] >= 0x31 && buf[i] <= 0x39) { while (i < n && isDigit(buf[i])) i++; }
    else fail('JSON_SYNTAX', 'malformed number');
    let int = true;
    if (i < n && buf[i] === 0x2E) {
      int = false; i++;
      if (!(i < n && isDigit(buf[i]))) fail('JSON_SYNTAX', 'malformed number fraction');
      while (i < n && isDigit(buf[i])) i++;
    }
    if (i < n && (buf[i] === 0x65 || buf[i] === 0x45)) {
      int = false; i++;
      if (i < n && (buf[i] === 0x2B || buf[i] === 0x2D)) i++;
      if (!(i < n && isDigit(buf[i]))) fail('JSON_SYNTAX', 'malformed number exponent');
      while (i < n && isDigit(buf[i])) i++;
    }
    const tok = buf.toString('latin1', start, i);
    const v = Number(tok);
    if (!Number.isFinite(v)) fail('JSON_NUMBER_OUT_OF_RANGE', 'number outside the IEEE 754 double range');
    // The safe-integer rule is judged on the value, not on the spelling: every double at or above
    // 2^53 is an integer, however its token is written (1e16, 9007199254740992.0).
    if (Math.abs(v) >= 9007199254740992) fail('JSON_NUMBER_OUT_OF_RANGE', 'integer with magnitude at or above 2^53');
    return new JNum(v, int);
  }
  function value() {
    ws();
    if (i >= n) fail('JSON_SYNTAX', 'unexpected end of input');
    const b = buf[i];
    if (b === 0x7B) return object();
    if (b === 0x5B) return array();
    if (b === 0x22) return string();
    if (b === 0x2D || isDigit(b)) return number();
    if (lit('true')) return true;
    if (lit('false')) return false;
    if (lit('null')) return null;
    return fail('JSON_SYNTAX', 'unexpected character');
  }
  function object() {
    i++;
    if (++depth > MAX_DEPTH) fail('JSON_DEPTH_EXCEEDED', `nesting depth exceeds ${MAX_DEPTH}`);
    const m = new Map();
    ws();
    if (i < n && buf[i] === 0x7D) { i++; depth--; return m; }
    for (;;) {
      ws();
      if (!(i < n && buf[i] === 0x22)) fail('JSON_SYNTAX', 'object member name expected');
      const k = string();
      if (m.has(k)) fail('JSON_DUPLICATE_MEMBER', 'duplicate object member');
      ws();
      if (!(i < n && buf[i] === 0x3A)) fail('JSON_SYNTAX', 'colon expected');
      i++;
      m.set(k, value());
      ws();
      if (i < n && buf[i] === 0x2C) { i++; continue; }
      if (i < n && buf[i] === 0x7D) { i++; break; }
      fail('JSON_SYNTAX', 'comma or closing brace expected');
    }
    depth--;
    return m;
  }
  function array() {
    i++;
    if (++depth > MAX_DEPTH) fail('JSON_DEPTH_EXCEEDED', `nesting depth exceeds ${MAX_DEPTH}`);
    const a = [];
    ws();
    if (i < n && buf[i] === 0x5D) { i++; depth--; return a; }
    for (;;) {
      a.push(value());
      ws();
      if (i < n && buf[i] === 0x2C) { i++; continue; }
      if (i < n && buf[i] === 0x5D) { i++; break; }
      fail('JSON_SYNTAX', 'comma or closing bracket expected');
    }
    depth--;
    return a;
  }
  const v = value();
  ws();
  if (i !== n) fail('JSON_SYNTAX', 'content after the JSON value');
  return v;
}

// ───────────────────────── RFC 8785 canonicalization ─────────────────────────

const cmpUtf16 = (a, b) => (a < b ? -1 : a > b ? 1 : 0); // JS compares strings by UTF-16 code unit

export function jcs(v) {
  if (v === null) return 'null';
  if (v === true) return 'true';
  if (v === false) return 'false';
  if (typeof v === 'string') return JSON.stringify(v);
  if (v instanceof JNum) return JSON.stringify(v.v); // ECMAScript number serialization; -0 prints as 0
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
  if (v instanceof Map) {
    const keys = [...v.keys()].sort(cmpUtf16);
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + jcs(v.get(k))).join(',') + '}';
  }
  throw new Error('jcs: unsupported value');
}

const sha256 = (buf) => createHash('sha256').update(buf).digest();
const sha256hex = (buf) => createHash('sha256').update(buf).digest('hex');
const jcsDigest = (v) => sha256hex(Buffer.from(jcs(v), 'utf8'));

// ───────────────────────── small helpers ─────────────────────────

const isMap = (v) => v instanceof Map;
const isStr = (v) => typeof v === 'string';
const HEX64 = /^[0-9a-f]{64}$/;
const isHex64 = (v) => isStr(v) && HEX64.test(v);
const hasSupplementary = (s) => /[\uD800-\uDFFF]/.test(s);
const isStrArray = (v) => Array.isArray(v) && v.every(isStr);
const strictlyAscending = (a) => a.every((x, i) => i === 0 || a[i - 1] < x);
const asInt = (v) => (v instanceof JNum && v.int && Number.isSafeInteger(v.v) ? v.v : null);
const digestOf = (o) => (isMap(o) && isMap(o.get('digest')) ? o.get('digest').get('sha256') : undefined);

// Standard, padded, canonical base64 only. Returns null on anything else.
export function b64strict(s) {
  if (!isStr(s) || s.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return null;
  const buf = Buffer.from(s, 'base64');
  return buf.toString('base64') === s ? buf : null;
}

// DSSE pre-authentication encoding over (payloadType, payload bytes).
export function pae(payloadType, body) {
  const t = Buffer.from(payloadType, 'utf8');
  return Buffer.concat([Buffer.from(`DSSEv1 ${t.length} `, 'latin1'), t, Buffer.from(` ${body.length} `, 'latin1'), body]);
}

// RFC 6962 Merkle tree hash over leaf hashes H(0x00 || d): recursive split, never padding.
export function merkleRoot(leaves) {
  if (leaves.length === 1) return leaves[0];
  let k = 1;
  while (k * 2 < leaves.length) k *= 2;
  return sha256(Buffer.concat([Buffer.from([0x01]), merkleRoot(leaves.slice(0, k)), merkleRoot(leaves.slice(k))]));
}

// The timestamp profile of `issuedAt` and `armedAt`: RFC 3339, uppercase T, zone Z, +00:00 or -00:00.
// Returns a comparable key, or null when the string is outside the profile.
export function parseTimestamp(s) {
  if (!isStr(s)) return null;
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:Z|[+-]00:00)$/.exec(s);
  if (!m) return null;
  const [Y, M, D, h, mi, sec] = m.slice(1, 7).map(Number);
  if (M < 1 || M > 12 || D < 1) return null;
  const leap = (Y % 4 === 0 && Y % 100 !== 0) || Y % 400 === 0;
  const dim = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][M - 1];
  if (D > dim || h > 23 || mi > 59) return null;
  if (sec > 60 || (sec === 60 && !(h === 23 && mi === 59))) return null; // a leap second only closes a UTC day
  return { parts: [Y, M, D, h, mi, sec], frac: m[7] || '' };
}
export function cmpTimestamp(a, b) {
  for (let k = 0; k < 6; k++) if (a.parts[k] !== b.parts[k]) return a.parts[k] < b.parts[k] ? -1 : 1;
  const len = Math.max(a.frac.length, b.frac.length);
  const fa = a.frac.padEnd(len, '0'); const fb = b.frac.padEnd(len, '0');
  return fa < fb ? -1 : fa > fb ? 1 : 0;
}

// ───────────────────────── key policy and signature verification (stage two) ─────────────────────────

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export function loadKeyPolicy(path) {
  if (!path) return [];
  try {
    const text = readFileSync(path, 'utf8');
    const doc = JSON.parse(text.charCodeAt(0) === 0xFEFF ? text.slice(1) : text); // a byte order mark is tolerated here
    const list = doc && Array.isArray(doc.substrateObservationKeys) ? doc.substrateObservationKeys : [];
    const keys = [];
    for (const e of list) {
      if (!e || typeof e.publicKeyHex !== 'string' || !/^([0-9a-fA-F]{2})+$/.test(e.publicKeyHex)) continue;
      const raw = Buffer.from(e.publicKeyHex, 'hex');
      try {
        // A 32-byte value is read as a raw Ed25519 public key; anything else as a DER SubjectPublicKeyInfo.
        const key = raw.length === 32
          ? createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' })
          : createPublicKey({ key: raw, format: 'der', type: 'spki' });
        keys.push({ key }); // `keyid` is a lookup hint and never the check: it is not read
      } catch { /* a key this verifier cannot load attests nothing */ }
    }
    return keys;
  } catch (e) {
    process.stderr.write(`aee-verify: key policy unreadable (${e.message}); every substrate row derives unattested\n`);
    return [];
  }
}

function signatureVerifies(rec, keys) {
  if (keys.length === 0) return false;
  for (const s of rec.signatures) {
    if (!(s instanceof Map) || typeof s.get('sig') !== 'string') continue; // an entry that is not a signature verifies nothing
    const sig = Buffer.from(s.get('sig'), 'base64');
    for (const k of keys) { // every pinned key is tried; the entry's `keyid` decides nothing
      try {
        const t = k.key.asymmetricKeyType;
        const alg = t === 'ed25519' || t === 'ed448' ? null : 'sha256';
        if (cryptoVerify(alg, rec.pae, k.key, sig)) return true;
      } catch { /* not a verification */ }
    }
  }
  return false;
}

// ───────────────────────── the verifier ─────────────────────────

export const MAX_DETAILS = 64;
// A statement string quoted in a diagnostic, cut short: a diagnostic never grows with the input.
const q = (s) => (typeof s === 'string' && s.length > 64 ? JSON.stringify(s.slice(0, 64)) + '(cut)' : JSON.stringify(s));

export function verifyStatement(buf, keys = []) {
  const codes = new Set(); // every condition met, complete
  const found = [];        // the first MAX_DETAILS findings, { code, message }
  let dropped = 0;
  const err = (code, message) => { codes.add(code); if (found.length < MAX_DETAILS) found.push({ code, message }); else dropped++; };
  const out = (result, tiers) => {
    const list = [...codes];
    const reject = list.length > 0;
    // Where a statement that needs a seal carries none that is valid, that unmet requirement is the
    // primary condition and the defective record's own condition is reported beside it.
    const primaryCode = !reject ? null : (codes.has('SEAL_REQUIRED_NONE_VALID') ? 'SEAL_REQUIRED_NONE_VALID' : list[0]);
    return { verdict: reject ? 'reject' : 'accept', codes: list, result: reject ? null : result, tiers: reject ? [] : tiers, primaryCode, details: found, detailsDropped: dropped };
  };

  // ── Stage one, step 1: statement well-formedness ──
  let root;
  try { root = parseStrict(buf); } catch (e) {
    if (!(e instanceof JsonErr)) throw e;
    err(e.code, `${e.message} (byte ${e.at})`);
    return out();
  }
  if (!isMap(root)) { err('JSON_TOP_LEVEL_NOT_OBJECT', 'the statement is not a JSON object'); return out(); }
  if (root.get('_type') !== STATEMENT_TYPE) err('STATEMENT_TYPE_INVALID', '_type is not the in-toto Statement v1 type');
  if (root.get('predicateType') !== PREDICATE_TYPE) err('PREDICATE_TYPE_UNSUPPORTED', 'predicateType is not the v0.7 type this verifier implements (no alias, no earlier version)');
  if (codes.size) return out();

  const subject = root.get('subject');
  if (!Array.isArray(subject) || subject.length !== 1) err('SUBJECT_COUNT_INVALID', 'subject must contain exactly one entry');
  const oneSubject = Array.isArray(subject) && subject.length === 1;
  const subj0 = oneSubject ? subject[0] : null; // a JSON null entry is an entry, and carries no digest
  if (oneSubject && !isStr(digestOf(subj0))) err('SUBJECT_DIGEST_INVALID', 'subject[0] carries no sha256 digest');

  const P = root.get('predicate');
  if (!isMap(P)) { err('PREDICATE_INVALID', 'predicate is missing or not an object'); return out(); }

  const carriedResult = P.get('result');
  if (!isStr(carriedResult)) err('RESULT_MISSING', 'result is missing or not a string');

  const issuedAt = parseTimestamp(P.get('issuedAt'));
  if (issuedAt === null) err('ISSUED_AT_INVALID', 'issuedAt is absent or outside the RFC 3339 profile (uppercase T; Z, +00:00 or -00:00)');

  if (P.has('doesNotAssert') && !isStrArray(P.get('doesNotAssert'))) err('DOES_NOT_ASSERT_MISTYPED', 'doesNotAssert is present and is not an array of strings');

  // observationEnvironment
  const env = P.get('observationEnvironment');
  const E = isMap(env) ? env : new Map();
  if (!isMap(env)) err('ENVIRONMENT_INVALID', 'observationEnvironment is missing or not an object');

  const substrateD = digestOf(E.get('substrate'));
  if (!isStr(substrateD)) err('ENVIRONMENT_SUBSTRATE_INVALID', 'observationEnvironment.substrate carries no sha256 digest');
  const catchD = digestOf(E.get('catchPolicy'));
  if (!isStr(catchD)) err('ENVIRONMENT_CATCH_POLICY_INVALID', 'observationEnvironment.catchPolicy carries no sha256 digest');

  const posture = E.get('networkPosture');
  const postureD = digestOf(posture);
  if (!isMap(posture) || !isStr(postureD)) err('NETWORK_POSTURE_INVALID', 'networkPosture is missing or carries no sha256 digest');
  if (isMap(posture) && !(isStr(posture.get('posture')) && POSTURES.has(posture.get('posture')))) err('NETWORK_POSTURE_INVALID', 'networkPosture.posture is absent or outside the closed vocabulary');

  const corpus = E.get('corpus');
  const corpusD = digestOf(corpus);
  const manifest = isMap(corpus) ? corpus.get('manifest') : undefined;
  const attackClass = new Map(); // attackId -> class
  const classIds = new Map();    // class -> [attackId]
  let expected = null;           // attackId -> Set(commitment)
  if (!isMap(corpus) || !isStr(corpusD)) err('CORPUS_INVALID', 'corpus is missing or carries no sha256 digest');
  if (!isMap(manifest) || !isMap(manifest.get('classes'))) err('MANIFEST_MALFORMED', 'corpus.manifest.classes is missing or not an object');
  else {
    for (const [cls, ids] of manifest.get('classes')) {
      if (!isStrArray(ids)) { err('MANIFEST_MALFORMED', `class ${q(cls)} is not an array of attack identifiers`); continue; }
      classIds.set(cls, ids);
      for (const id of ids) {
        if (attackClass.has(id) && attackClass.get(id) !== cls) err('MANIFEST_ATTACK_IN_MULTIPLE_CLASSES', `attack ${q(id)} appears under more than one class`);
        attackClass.set(id, cls);
      }
    }
    if (attackClass.size === 0) err('MANIFEST_DECLARES_NO_ATTACK', 'the corpus manifest declares zero attack identifiers');
    if (manifest.has('expectedPayloads')) {
      const ep = manifest.get('expectedPayloads');
      if (!isMap(ep)) err('EXPECTED_PAYLOADS_MALFORMED', 'expectedPayloads is not an object');
      else {
        expected = new Map();
        for (const [id, vals] of ep) {
          if (!attackClass.has(id)) err('EXPECTED_PAYLOADS_MALFORMED', `expectedPayloads key ${q(id)} is not an attack the manifest declares`);
          if (!(Array.isArray(vals) && vals.length > 0 && vals.every(isHex64) && strictlyAscending(vals))) err('EXPECTED_PAYLOADS_MALFORMED', `expectedPayloads[${q(id)}] is not a non-empty, sorted, duplicate-free array of lowercase 64-hex values`);
          else expected.set(id, new Set(vals));
        }
      }
    }
  }

  const vocab = E.get('observationVocabulary');
  const vocabD = digestOf(vocab);
  let labels = new Set(); let caughtSet = new Set(); let vocabOk = false;
  if (!isMap(vocab) || !isStr(vocabD)) err('VOCABULARY_MALFORMED', 'observationVocabulary is missing or carries no sha256 digest');
  if (isMap(vocab)) {
    const L = vocab.get('labels'); const C = vocab.get('caught');
    const okArr = (a) => isStrArray(a) && strictlyAscending(a) && !a.some(hasSupplementary);
    if (!okArr(L) || !okArr(C)) err('VOCABULARY_MALFORMED', 'labels and caught must be sorted (UTF-16 code unit), duplicate-free, BMP-only arrays of strings');
    else {
      const lset = new Set(L);
      if (!C.every((x) => lset.has(x))) err('VOCABULARY_MALFORMED', 'caught is not a subset of labels');
      else { labels = lset; caughtSet = new Set(C); vocabOk = true; }
    }
  }

  // coverage
  const coverage = P.get('coverage');
  let assessed = []; let oos = new Map(); let routed = new Map();
  if (!isMap(coverage)) err('COVERAGE_MALFORMED', 'coverage is missing or not an object');
  else {
    const a = coverage.get('assessedClasses'); const o = coverage.get('outOfScope'); const r = coverage.get('routedElsewhere');
    const okMap = (m) => isMap(m) && [...m.values()].every(isStr);
    if (!isStrArray(a) || !okMap(o) || !okMap(r)) err('COVERAGE_MALFORMED', 'assessedClasses must be an array of class codes; outOfScope and routedElsewhere maps from class code to a reason string');
    else {
      assessed = a; oos = o; routed = r;
      const aSet = new Set(a);
      for (const cls of classIds.keys()) {
        const places = (aSet.has(cls) ? 1 : 0) + (o.has(cls) ? 1 : 0) + (r.has(cls) ? 1 : 0);
        if (places !== 1) err('COVERAGE_PARTITION_INVALID', `manifest class ${q(cls)} appears in ${places} of assessedClasses, outOfScope, routedElsewhere (exactly one required)`);
      }
      for (const cls of [...aSet, ...o.keys(), ...r.keys()]) {
        if (!classIds.has(cls)) err('COVERAGE_PARTITION_INVALID', `coverage names class ${q(cls)}, which the manifest does not declare`);
      }
    }
  }

  // observation records: envelope shape, DSSE PAE, leaf hash, payload reading
  const recordsRaw = P.get('observationRecords');
  if (P.has('observationRecords') && !Array.isArray(recordsRaw)) err('OBSERVATION_RECORDS_MALFORMED', 'observationRecords is present and is not an array');
  const recs = [];
  for (const [idx, r] of (Array.isArray(recordsRaw) ? recordsRaw : []).entries()) {
    const body = isMap(r) ? b64strict(r.get('payload')) : null;
    const sigs = isMap(r) ? r.get('signatures') : null;
    // stage one asks for at least one signature entry and reads none of them
    const sigsOk = Array.isArray(sigs) && sigs.length > 0;
    if (!isMap(r) || body === null || !isStr(r.get('payloadType')) || !sigsOk) {
      err('RECORD_ENVELOPE_MALFORMED', `observationRecords[${idx}] is not a DSSE envelope (base64 payload, payloadType, at least one signature entry)`);
      recs.push(null);
      continue;
    }
    const type = r.get('payloadType');
    const paeBytes = pae(type, body);
    const leaf = sha256(Buffer.concat([Buffer.from([0x00]), paeBytes]));
    const rec = { idx, pae: paeBytes, leaf, leafHex: leaf.toString('hex'), signatures: sigs, p: null, kind: null };
    // A covering payload is a canonical (RFC 8785), I-JSON object under a media type ending in +json,
    // with BMP-only member names. Anything else is carried, committed in batchRoot, and covers nothing:
    // none of its fields is read, so it has no kind.
    if (type.endsWith('+json')) {
      try {
        const p = parseStrict(body);
        const namesBmp = (v) => (isMap(v) ? [...v].every(([k, x]) => !hasSupplementary(k) && namesBmp(x)) : Array.isArray(v) ? v.every(namesBmp) : true);
        if (isMap(p) && Buffer.from(jcs(p), 'utf8').equals(body) && namesBmp(p)) rec.p = p;
      } catch (e) { if (!(e instanceof JsonErr)) throw e; }
    }
    if (rec.p && isStr(rec.p.get('aeeKind'))) rec.kind = rec.p.get('aeeKind');
    recs.push(rec);
  }
  const live = recs.filter(Boolean);
  const seenLeaf = new Set();
  for (const r of live) {
    if (seenLeaf.has(r.leafHex)) err('RECORD_DUPLICATE', `observationRecords[${r.idx}] is byte-identical to an earlier record (same leaf hash)`);
    seenLeaf.add(r.leafHex);
  }

  // attackResults: row shape
  const rowsRaw = P.get('attackResults');
  if (!Array.isArray(rowsRaw)) err('ATTACK_RESULTS_MALFORMED', 'attackResults is missing or not an array');
  const rows = [];
  const seenAttack = new Set();
  for (const [idx, row] of (Array.isArray(rowsRaw) ? rowsRaw : []).entries()) {
    if (!isMap(row)) { err('ROW_MALFORMED', `attackResults[${idx}] is not an object`); continue; }
    const attackId = row.get('attackId');
    if (!isStr(attackId)) err('ROW_ATTACK_ID_INVALID', `attackResults[${idx}] carries no attackId`);
    else {
      if (!attackClass.has(attackId)) err('ROW_ATTACK_ID_NOT_IN_MANIFEST', `attackResults[${idx}] names attack ${q(attackId)}, which the manifest does not declare`);
      if (seenAttack.has(attackId)) err('ROW_ATTACK_ID_DUPLICATE', `attack ${q(attackId)} appears on more than one row`);
      seenAttack.add(attackId);
    }
    const label = row.get('containmentObserved');
    const labelOk = isStr(label) && labels.has(label);
    const caught = labelOk && caughtSet.has(label);
    const clean = labelOk && !caught;
    const basis = row.get('basis'); const method = row.get('method'); const attribution = row.get('attribution');
    const basisOk = isStr(basis) && BASIS.has(basis);
    const methodOk = isStr(method) && METHOD.has(method);
    const attributionOk = isStr(attribution) && ATTRIBUTION.has(attribution);
    if (!isStr(row.get('actualLayer'))) err('ROW_ACTUAL_LAYER_MISSING', `attackResults[${idx}] carries no actualLayer`);
    else if (clean && row.get('actualLayer') !== 'none') err('ROW_ACTUAL_LAYER_NOT_NONE', `attackResults[${idx}] is a clean row and its actualLayer is not the literal "none"`);
    let refs = null;
    if (row.has('observationRefs')) {
      const raw = row.get('observationRefs');
      const ints = Array.isArray(raw) ? raw.map(asInt) : null;
      if (ints === null || ints.some((x) => x === null || x < 0 || x >= recs.length)) err('ROW_OBSERVATION_REF_INVALID', `attackResults[${idx}].observationRefs is not an array of indexes in range for observationRecords`);
      else refs = ints;
    }
    rows.push({ idx, attackId, labelOk, caught, clean, basis, method, attribution, basisOk, methodOk, attributionOk, refs, substrate: basis === 'substrate' });
  }
  const hasSubstrateRow = rows.some((r) => r.substrate);

  // batchRoot is required exactly where there are records to commit to; its value is checked in step 2
  if (live.length > 0 && !isStr(P.get('batchRoot'))) err('BATCH_ROOT_MISSING', 'observationRecords is non-empty and batchRoot is absent');

  // run-binding derivability, for a statement carrying at least one `basis: substrate` row
  let binding = null;
  if (hasSubstrateRow) {
    const entropyD = digestOf(E.get('runEntropy'));
    if (!E.has('runEntropy') || !isStr(entropyD)) err('RUN_ENTROPY_MISSING', 'a basis: substrate row is carried and runEntropy is absent');
    const inputs = { catchPolicy: catchD, corpus: corpusD, runEntropy: entropyD, substrate: substrateD, subject: subj0 === null ? undefined : digestOf(subj0), networkPosture: postureD };
    let derivable = isStr(vocabD) && isMap(posture);
    for (const [name, d] of Object.entries(inputs)) {
      if (!isHex64(d)) { derivable = false; if (isStr(d)) err('RUN_BINDING_DIGEST_INVALID', `${name} digest is not lowercase 64-hex on a statement carrying a basis: substrate row`); }
    }
    if (derivable) {
      binding = jcsDigest(new Map([
        ['aeeBindingVersion', BINDING_VERSION], ['catchPolicy', catchD], ['corpus', corpusD],
        ['networkPosture', jcsDigest(posture)], ['observationVocabulary', vocabD],
        ['runEntropy', entropyD], ['subject', inputs.subject], ['substrate', substrateD],
      ]));
    }
  }
  if (codes.size) return out(); // a malformed statement is not evaluated further

  // ── Reading the records: kinds and their constraints (byte-pure; signatures are stage two) ──
  const observedLeaves = [...new Set(live.filter((r) => r.kind === 'interception' || r.kind === 'examination').map((r) => r.leafHex))].sort(cmpUtf16);
  const observedSet = jcsDigest(observedLeaves);
  const idArrayOk = (a) => isStrArray(a) && strictlyAscending(a) && a.every((x) => attackClass.has(x));

  // A record of a covering kind ends in one of three states. It covers. Or it violates a constraint
  // of its kind (`violations`): it covers nothing, and when it binds to this run the statement is
  // invalid. Or it is only weakened (`weak`): it covers nothing, satisfies no requirement that asks
  // for a record, and violates none — the text gives these faults no consequence beyond that.
  for (const r of live) {
    r.binds = false; r.covers = false; r.violations = []; r.weak = []; r.method = null; r.reserved = false; r.postureDigest = undefined;
    if (!r.p) continue;
    const p = r.p;
    r.binds = binding !== null && p.get('aeeRunBinding') === binding;
    r.method = isStr(p.get('aeeMethod')) && METHOD.has(p.get('aeeMethod')) ? p.get('aeeMethod') : null;
    // the three reserved members, present as strings; what values they may take is a matter of kind
    r.reserved = isStr(p.get('aeeRunBinding')) && isStr(p.get('aeeKind')) && isStr(p.get('aeeMethod'));
    r.postureDigest = p.get('aeePostureDigest');
    if (!COVERING_KINDS.has(r.kind)) continue; // registered non-covering kinds and unrecognized kinds carry no constraint
    const v = (code) => { r.violations.push(code); };
    const w = (code) => { r.weak.push(code); };
    if (!r.reserved) w('RECORD_RESERVED_MEMBERS_MISSING');
    // an unrecognized `aee*` member can only weaken coverage
    if ([...p.keys()].some((k) => k.startsWith('aee') && !KNOWN_AEE.has(k))) w('RECORD_UNRECOGNIZED_RESERVED_MEMBER');
    // a record declaring a binding version this verifier does not implement covers nothing
    if (p.has('aeeBindingVersion') && p.get('aeeBindingVersion') !== BINDING_VERSION) w('RECORD_BINDING_VERSION_UNSUPPORTED');
    if (r.kind === 'interception') {
      // the one kind that leaves aeeMethod free, inside its closed vocabulary
      if (r.reserved && r.method === null) w('INTERCEPTION_METHOD_OUT_OF_VOCABULARY');
      const c = p.get('aeePayloadCommitment');
      if (!(Array.isArray(c) && c.length > 0 && c.every(isHex64) && strictlyAscending(c))) v('INTERCEPTION_COMMITMENT_INVALID');
    } else if (r.kind === 'arming') {
      const armedAt = parseTimestamp(p.get('armedAt'));
      if (armedAt === null || cmpTimestamp(armedAt, issuedAt) > 0) v('ARMING_ARMED_AT_INVALID');
      if (p.get('aeePostureDigest') !== postureD) v('ARMING_POSTURE_DIGEST_MISMATCH');
      if (!idArrayOk(p.get('aeeAssessedAttacks'))) v('ARMING_ASSESSED_ATTACKS_INVALID');
      if (p.get('aeeMethod') !== 'intercepted') v('ARMING_METHOD_INVALID');
      // optional run-sequence members: syntax only, and a fault there is a reserved-member fault
      const hasSeq = p.has('aeeRunSeq'); const hasPrev = p.has('aeePrevRunBinding'); const hasScope = p.has('aeeChainScope');
      if (hasSeq || hasPrev || hasScope) {
        const seq = asInt(p.get('aeeRunSeq'));
        const scope = p.get('aeeChainScope');
        const scopeOk = isStrArray(scope) && strictlyAscending(scope) && scope.every((t) => CHAIN_TOKENS.has(t));
        const prevOk = seq === 1 ? !hasPrev : isHex64(p.get('aeePrevRunBinding'));
        if (!(hasSeq && seq !== null && seq >= 1 && hasScope && scopeOk && prevOk)) w('ARMING_RUN_SEQUENCE_INVALID');
      }
    } else if (r.kind === 'sealed') {
      const drop = asInt(p.get('aeeDropCount'));
      const bound = p.has('aeeDropBound') ? asInt(p.get('aeeDropBound')) : undefined;
      if (typeof p.get('aeeStillArmed') !== 'boolean') v('SEAL_MEMBER_INVALID');
      else if (p.get('aeeStillArmed') !== true) v('SEAL_NOT_STILL_ARMED');
      if (drop === null || drop < 0 || bound === null) v('SEAL_MEMBER_INVALID');
      else if (!(drop === 0 || (bound !== undefined && drop <= bound))) v('SEAL_DROP_COUNT_EXCEEDED');
      if (p.get('aeePostureDigest') !== postureD) v('SEAL_POSTURE_DIGEST_MISMATCH');
      // a seal committing to a record set the statement does not carry covers nothing
      if (p.get('aeeObservedSet') !== observedSet) v('SEAL_OBSERVED_SET_MISMATCH');
      if (!idArrayOk(p.get('aeeObservedAttacks'))) v('SEAL_OBSERVED_ATTACKS_INVALID');
      if (p.get('aeeMethod') !== 'intercepted') v('SEAL_METHOD_INVALID');
    } else if (r.kind === 'examination') {
      if (p.get('aeeMethod') !== 'reconstructed') v('EXAMINATION_METHOD_INVALID');
    }
    r.covers = r.violations.length === 0 && r.weak.length === 0;
  }

  // ── Stage one, step 2: coverage validity ──
  const rowsOf = (pred) => rows.filter(pred);
  const caughtRows = rowsOf((r) => r.caught);
  const refRecs = (row) => (row.refs || []).map((i) => recs[i]);

  // batchRoot recomputes over the carried records, in array order
  if (live.length > 0) {
    if (P.get('batchRoot') !== merkleRoot(live.map((r) => r.leaf)).toString('hex')) err('BATCH_ROOT_MISMATCH', 'batchRoot does not recompute over observationRecords (RFC 6962, leaf = H(0x00 || DSSE PAE))');
  } else if (P.has('batchRoot')) {
    err('BATCH_ROOT_MISMATCH', 'batchRoot is carried and there is no observation record to recompute it over');
  }

  for (const row of rows) {
    const where = `attackResults[${row.idx}]`;
    const rr = refRecs(row);
    // every row: a clean row resolves no index to an interception record
    if (row.clean && rr.some((r) => r.kind === 'interception')) err('ROW_CLEAN_REFERENCES_INTERCEPTION', `${where} states nothing was caught and points at an interception record`);
    // every row: attribution pinned needs an interception whose commitment the corpus declared for this attack
    if (row.attribution === 'pinned') {
      const inter = rr.filter((r) => r.kind === 'interception');
      const entry = expected && isStr(row.attackId) ? expected.get(row.attackId) : undefined;
      const carries = (r) => Array.isArray(r.p.get('aeePayloadCommitment')) && r.p.get('aeePayloadCommitment').some((x) => entry.has(x));
      if (inter.length === 0 || !entry || !inter.every(carries)) err('ROW_PINNED_NOT_SUPPORTED', `${where} declares attribution: pinned without an interception record carrying a commitment the corpus declared for this attack`);
    }
    if (!row.substrate) continue;
    // a basis: substrate row
    if (!row.labelOk || !row.methodOk) { err('ROW_SUBSTRATE_FAIL_CLOSED', `${where} is basis: substrate with an out-of-vocabulary containmentObserved or method, and cannot be covered`); continue; }
    if (!row.refs || row.refs.length === 0) { err('ROW_SUBSTRATE_NO_REFS', `${where} is basis: substrate and its observationRefs is absent or empty`); continue; }
    if (rr.some((r) => !r.p)) err('ROW_REF_NOT_CANONICAL_JSON', `${where} references a record whose payload is not a canonical +json object`);
    else if (rr.some((r) => !r.reserved)) err('ROW_REF_RESERVED_MEMBERS_MISSING', `${where} references a record that does not carry the reserved members`);
    else {
      // a record declaring a binding version this verifier does not implement is reported as that,
      // apart from a digest mismatch: the declaration is read before the digest is compared
      const otherVersion = (r) => r.weak.includes('RECORD_BINDING_VERSION_UNSUPPORTED');
      if (rr.some((r) => !r.binds && otherVersion(r))) err('RECORD_BINDING_VERSION_UNSUPPORTED', `${where} references a record declaring a run binding version other than "${BINDING_VERSION}"`);
      if (rr.some((r) => !r.binds && !otherVersion(r))) err('ROW_REF_RUN_BINDING_MISMATCH', `${where} references a record whose aeeRunBinding is not the run binding derived from this statement`);
    }
    const good = (kind) => rr.filter((r) => r.kind === kind && r.covers && r.binds);
    let matched;
    if (row.method === 'reconstructed') matched = good('examination').length > 0;
    else if (row.caught) matched = good('interception').length > 0;
    else {
      // a clean intercepted row: an arming record, and a sealed record whose posture digest also equals
      // that of every arming record this row resolves
      const armings = rr.filter((r) => r.kind === 'arming');
      matched = good('arming').length > 0 && good('sealed').some((s) => armings.every((a) => a.postureDigest === s.postureDigest));
    }
    if (!matched) {
      err('ROW_CLASS_MATCH_FAILED', `${where} is not covered by records of the class its claim requires`);
      if (rr.some((r) => NON_COVERING_KINDS.has(r.kind))) err('ROW_REFERENCES_NON_COVERING_KIND', `${where} resolves a record of a kind registered as covering nothing`);
      else if (rr.some((r) => r.p && isStr(r.kind) && !COVERING_KINDS.has(r.kind))) err('ROW_REFERENCES_UNRECOGNIZED_KIND', `${where} resolves a record of a kind this verifier does not recognize`);
      // why a record this row resolves covers nothing, where that is not a violated constraint of its kind
      for (const code of new Set(rr.flatMap((r) => r.weak))) err(code, `${where} resolves a record that covers nothing on this ground`);
    }
    // the row's method is no stronger than the weakest aeeMethod across its covering records
    if (row.method === 'intercepted' && rr.some((r) => r.covers && r.binds && r.method === 'reconstructed')) err('ROW_METHOD_EXCEEDS_RECORDS', `${where} declares method: intercepted over a covering record signed aeeMethod: reconstructed`);
  }

  // statement-level requirements
  const caughtRefs = new Set(caughtRows.flatMap((row) => row.refs || []));
  const caughtIds = new Set(caughtRows.map((row) => row.attackId));
  // the attacks of the assessed classes; a class listed twice is one class
  const needIds = new Set([...new Set(assessed)].flatMap((cls) => classIds.get(cls) || []));
  for (const r of live) {
    const where = `observationRecords[${r.idx}]`;
    if (r.kind === 'interception' && !caughtRefs.has(r.idx)) err('INTERCEPTION_NOT_REFERENCED_BY_CAUGHT_ROW', `${where} is an interception no caught row accounts for`);
    if (r.kind === 'sealed' && r.p.get('aeeObservedSet') !== observedSet) err('SEAL_OBSERVED_SET_MISMATCH', `${where} commits to an aeeObservedSet that does not recompute over the carried interception and examination records`);
    if (!r.binds || !COVERING_KINDS.has(r.kind)) continue;
    // every carried record that binds to this run and names a covering kind satisfies that kind's constraints
    for (const code of r.violations) err(code, `${where} (${r.kind}) violates a constraint of its kind`);
    if (r.kind === 'arming' && idArrayOk(r.p.get('aeeAssessedAttacks'))) {
      const declared = new Set(r.p.get('aeeAssessedAttacks'));
      if (declared.size < needIds.size || ![...needIds].every((id) => declared.has(id))) err('ARMING_ASSESSED_ATTACKS_NOT_SUPERSET', `${where} declared, at run start, fewer attacks than coverage.assessedClasses now claims`);
    }
    if (r.kind === 'sealed' && idArrayOk(r.p.get('aeeObservedAttacks'))) {
      for (const id of r.p.get('aeeObservedAttacks')) {
        if (!caughtIds.has(id)) err('SEAL_OBSERVED_ATTACK_WITHOUT_CAUGHT_ROW', `${where} names attack ${q(id)} as observed and no caught row carries it`);
      }
    }
  }
  if (hasSubstrateRow && !live.some((r) => r.kind === 'sealed' && r.covers && r.binds)) {
    err('SEAL_REQUIRED_NONE_VALID', 'a basis: substrate row is carried and no sealed record that binds to this run covers');
    // beside it, why a seal of this run covers nothing where that is not already a violated constraint
    for (const r of live) if (r.kind === 'sealed' && r.binds) for (const code of r.weak) err(code, `observationRecords[${r.idx}] (sealed) covers nothing on this ground`);
  }

  // coverage integrity, at attack granularity
  const haveIds = new Set(rows.map((r) => r.attackId));
  if (needIds.size !== haveIds.size || [...needIds].some((id) => !haveIds.has(id))) err('COVERAGE_INTEGRITY_MISMATCH', 'the attackIds on attackResults rows are not exactly the attacks of the assessed classes');

  // ── Stage one, step 3: the result recompute (reads rows and coverage only) ──
  let rank = 3;
  if (rows.some((r) => r.caught || !r.labelOk || !r.basisOk || !r.methodOk || !r.attributionOk)) rank = Math.min(rank, 0);
  if (oos.size > 0 || routed.size > 0) rank = Math.min(rank, 1);
  if (rows.some((r) => r.clean && (r.basis !== 'substrate' || r.method !== 'intercepted'))) rank = Math.min(rank, 2);
  const result = RESULT_ORDER[rank];
  if (carriedResult !== result) err('RESULT_MISMATCH', `the carried result ${q(carriedResult)} does not recompute (the predicate reduces to ${q(result)})`);

  // ── Stage one, step 4: manifest and vocabulary digest integrity ──
  if (corpusD !== jcsDigest(manifest)) err('CORPUS_DIGEST_MISMATCH', 'corpus.digest does not re-derive from the embedded manifest (RFC 8785, SHA-256)');
  if (vocabOk && vocabD !== jcsDigest(new Map([['caught', vocab.get('caught')], ['labels', vocab.get('labels')]]))) err('VOCABULARY_DIGEST_MISMATCH', 'observationVocabulary.digest does not re-derive from {"caught","labels"}');

  if (codes.size) return out();

  // ── Stage two: the per-row evidence tier, against the consumer's pinned keys ──
  const verified = new Map();
  const ok = (r) => { if (!verified.has(r.idx)) verified.set(r.idx, signatureVerifies(r, keys)); return verified.get(r.idx); };
  const tiers = rows.map((row) => (!row.substrate ? 'declared' : (refRecs(row).every(ok) ? 'attested' : 'unattested')));
  return out(result, tiers);
}

// ───────────────────────── command line ─────────────────────────

const ascii = (s) => s.replace(/[^\x20-\x7e]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));

function main(argv) {
  const explain = argv[0] === '--explain';
  const args = explain ? argv.slice(1) : argv;
  if (args.length !== 1 || args[0].startsWith('-')) {
    process.stderr.write('usage: node aee-verify.mjs [--explain] <statement.json>   (key policy: AEE_SUBSTRATE_KEYS=<path>)\n');
    return 2;
  }
  let buf;
  try { buf = readFileSync(args[0]); } catch (e) {
    process.stderr.write(`aee-verify: cannot read ${args[0]}: ${e.message}\n`);
    return 2;
  }
  let r; let line;
  try {
    r = verifyStatement(buf, loadKeyPolicy(process.env.AEE_SUBSTRATE_KEYS));
    // The line carries no string taken from the statement: codes are this verifier's own names,
    // result and tiers come from closed vocabularies. primaryCode is present on a refusal only.
    const o = { verdict: r.verdict, codes: r.codes, result: r.result, tiers: r.tiers };
    if (r.primaryCode !== null) o.primaryCode = r.primaryCode;
    line = JSON.stringify(o);
  } catch (e) {
    // a failure of the verifier itself is never reported as a verdict
    process.stderr.write(`aee-verify: internal error, nothing was judged: ${ascii(String(e && e.message))}\n`);
    return 2;
  }
  if (explain) {
    for (const d of r.details) process.stderr.write(`${d.code}: ${ascii(d.message)}\n`);
    if (r.detailsDropped) process.stderr.write(`(${r.detailsDropped} further findings not listed)\n`);
  }
  process.stdout.write(line + '\n');
  return r.verdict === 'accept' ? 0 : 1;
}

const isMain = (() => { try { return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url)); } catch { return false; } })();
if (isMain) process.exitCode = main(process.argv.slice(2));
