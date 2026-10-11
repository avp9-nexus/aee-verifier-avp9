#!/usr/bin/env node
// test.mjs — the verifier's own bench. Every statement here is BUILT by this file from the
// specification text (no external vector). Each refusal is paired with an accepted statement
// that differs from it by one fact, so a verifier that refuses everything fails too.
//
// USAGE : node test.mjs      → exit 0 when every case holds, 1 otherwise
//
// The builder below is a second, deliberately separate implementation of the producer side
// (canonicalization, digests, run binding, DSSE PAE, Merkle root): it shares no function with
// aee-verify.mjs. It still shares one reader of the specification, which is its limit.

import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { verifyStatement } from './aee-verify.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const sha = (b) => createHash('sha256').update(b).digest('hex');
const shaRaw = (b) => createHash('sha256').update(b).digest();
const H = (s) => sha(Buffer.from(s));
const clone = (v) => JSON.parse(JSON.stringify(v));
// canonical JSON for plain JS values (sorted member names, no whitespace)
const canon = (v) => (v === null || typeof v !== 'object' ? JSON.stringify(v)
  : Array.isArray(v) ? '[' + v.map(canon).join(',') + ']'
    : '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}');
const paeOf = (type, body) => Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(type)} ${type} ${body.length} `), body]);
const leafOf = (type, body) => shaRaw(Buffer.concat([Buffer.from([0]), paeOf(type, body)]));
const mth = (L) => { // RFC 6962 section 2.1
  if (L.length === 1) return L[0];
  const k = 2 ** Math.floor(Math.log2(L.length - 1));
  return shaRaw(Buffer.concat([Buffer.from([1]), mth(L.slice(0, k)), mth(L.slice(k))]));
};

const K1 = generateKeyPairSync('ed25519');
const K2 = generateKeyPairSync('ed25519');
const K448 = generateKeyPairSync('ed448');
const KEC = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const KEYS1 = [{ key: K1.publicKey }];
const KEYS2 = [{ key: K2.publicKey }];
const TYPE = 'application/vnd.example.observation+json';
const OBSERVED = '@observedSet';
// characters this file never writes raw: a byte order mark and the three non-ASCII line separators
const [BOM, NEL, LS, PS] = [0xFEFF, 0x85, 0x2028, 0x2029].map((cp) => String.fromCharCode(cp));
const IDS = ['CO-EXFIL-1', 'CO-EXFIL-2', 'FS-WRITE-1'];

const bindingOf = (env, subject) => sha(canon({
  aeeBindingVersion: '2', catchPolicy: env.catchPolicy.digest.sha256, corpus: env.corpus.digest.sha256,
  networkPosture: sha(canon(env.networkPosture)), observationVocabulary: env.observationVocabulary.digest.sha256,
  runEntropy: env.runEntropy?.digest?.sha256, subject: subject[0].digest.sha256, substrate: env.substrate.digest.sha256,
}));

const interception = (extra = {}) => ({ p: { aeeKind: 'interception', aeeMethod: 'intercepted', aeePayloadCommitment: [H('payload-1')], ...extra } });
const arming = (c, extra = {}) => ({ p: { aeeKind: 'arming', aeeMethod: 'intercepted', armedAt: '2026-06-23T16:00:00Z', aeePostureDigest: c.posture, aeeAssessedAttacks: IDS, ...extra } });
const sealed = (c, extra = {}) => ({ p: { aeeKind: 'sealed', aeeMethod: 'intercepted', aeeStillArmed: true, aeeDropCount: 0, aeePostureDigest: c.posture, aeeObservedSet: OBSERVED, aeeObservedAttacks: ['CO-EXFIL-1'], ...extra } });
const examination = (extra = {}) => ({ p: { aeeKind: 'examination', aeeMethod: 'reconstructed', ...extra } });
const row = (attackId, extra = {}) => ({ attackId, containmentObserved: 'no_egress', basis: 'substrate', method: 'intercepted', attribution: 'paired', actualLayer: 'none', observationRefs: [1, 2], ...extra });
const caughtRow = (extra = {}) => row('CO-EXFIL-1', { containmentObserved: 'egress_captured', attribution: 'pinned', actualLayer: 'policy.egress_sinkhole', observationRefs: [0], ...extra });

// Builds a statement. Hooks: o.manifest, o.vocab, o.env(env) before the run binding is derived,
// o.records(ctx) → record specs ({p} canonical payload, {raw,type} verbatim bytes), o.rows(ctx),
// o.coverage, o.result, o.issuedAt, o.statement(st, ctx) on the finished object.
function build(o = {}) {
  const manifest = clone(o.manifest ?? { classes: { CO: ['CO-EXFIL-1', 'CO-EXFIL-2'], FS: ['FS-WRITE-1'] }, expectedPayloads: { 'CO-EXFIL-1': [H('payload-1')] } });
  const vocab = clone(o.vocab ?? { labels: ['egress_captured', 'no_egress'], caught: ['egress_captured'] });
  const env = {
    substrate: { name: 'substrate', digest: { sha256: H('substrate') } },
    corpus: { name: 'corpus', uri: 'pkg:example/corpus@1', digest: { sha256: sha(canon(manifest)) }, manifest },
    catchPolicy: { digest: { sha256: H('policy') } },
    networkPosture: { posture: 'sinkhole', digest: { sha256: H('posture') } },
    observationVocabulary: { digest: { sha256: sha(canon({ caught: vocab.caught, labels: vocab.labels })) }, labels: vocab.labels, caught: vocab.caught },
    runEntropy: { digest: { sha256: H('entropy') } },
  };
  const subject = [{ name: 'artifact', digest: { sha256: H('subject') } }];
  o.env?.(env, subject);
  const ctx = { binding: bindingOf(env, subject), posture: env.networkPosture.digest.sha256 };
  const specs = (o.records ?? ((c) => [interception(), arming(c), sealed(c)]))(ctx);
  const bodies = specs.map((s) => {
    if (s.raw) return null;
    const b = { aeeRunBinding: ctx.binding, ...s.p };
    for (const k of Object.keys(b)) if (b[k] === undefined) delete b[k]; // before any byte is derived from the body
    return b;
  });
  const bytesOf = (s, b) => (s.raw ? s.raw : Buffer.from(canon(b)));
  // what the seal commits to: the interception and examination records emitted as readable payloads
  // (canonical +json object, BMP-only member names), so a refusal below differs from its control by one fact
  const readable = (s, b) => !s.raw && (s.type ?? TYPE).endsWith('+json') && !Object.keys(b).some((k) => /[\uD800-\uDFFF]/.test(k));
  const observed = [...new Set(specs.map((s, i) => ({ s, b: bodies[i] }))
    .filter(({ s, b }) => readable(s, b) && (b.aeeKind === 'interception' || b.aeeKind === 'examination'))
    .map(({ s, b }) => leafOf(s.type ?? TYPE, bytesOf(s, b)).toString('hex')))].sort();
  ctx.observedSet = sha(canon(observed));
  const recs = specs.map((s, i) => {
    const b = bodies[i];
    if (b && b.aeeObservedSet === OBSERVED) b.aeeObservedSet = ctx.observedSet;
    const type = s.type ?? TYPE;
    const body = bytesOf(s, b);
    const sig = sign(s.alg ?? null, paeOf(type, body), (s.key ?? K1).privateKey).toString('base64');
    return { payload: body.toString('base64'), payloadType: type, signatures: [{ keyid: 'k1', sig }] };
  });
  const predicate = {
    result: o.result ?? 'fail',
    observationEnvironment: env,
    coverage: clone(o.coverage ?? { assessedClasses: ['CO', 'FS'], outOfScope: {}, routedElsewhere: {} }),
    attackResults: (o.rows ?? (() => [caughtRow(), row('CO-EXFIL-2'), row('FS-WRITE-1')]))(ctx),
    doesNotAssert: ['behaviour outside the thrown corpus'],
    issuedAt: o.issuedAt ?? '2026-06-23T16:08:07Z',
  };
  if (recs.length) {
    predicate.observationRecords = recs;
    predicate.batchRoot = mth(recs.map((r) => leafOf(r.payloadType, Buffer.from(r.payload, 'base64')))).toString('hex');
  }
  const st = { _type: 'https://in-toto.io/Statement/v1', subject, predicateType: 'https://in-toto.io/attestation/adversarial-execution-evidence/v0.7', predicate };
  o.statement?.(st, ctx);
  return Buffer.from(JSON.stringify(st));
}

// ready-made shapes
const allClean = (o = {}) => build({ result: 'pass', records: (c) => [arming(c), sealed(c, { aeeObservedAttacks: [] })], rows: () => IDS.map((id) => row(id, { observationRefs: [0, 1] })), ...o });
const artifactOnly = (o = {}) => build({ result: 'pass_indirect', env: (e) => { delete e.runEntropy; }, records: () => [], rows: () => IDS.map((id) => ({ attackId: id, containmentObserved: 'no_egress', basis: 'artifact', method: 'intercepted', attribution: 'paired', actualLayer: 'none' })), ...o });

let pass = 0; let failed = 0; const refusals = new Set(); let accepts = 0;
function check(name, buf, want, keys = []) {
  const r = verifyStatement(buf, keys);
  const problems = [];
  if (r.verdict !== want.verdict) problems.push(`verdict ${r.verdict}, wanted ${want.verdict}`);
  if (want.result !== undefined && r.result !== want.result) problems.push(`result ${r.result}, wanted ${want.result}`);
  if (want.code && !r.codes.includes(want.code)) problems.push(`codes ${JSON.stringify(r.codes)}, wanted ${want.code}`);
  if (want.only && !(r.codes.length === 1 && r.codes[0] === want.only)) problems.push(`codes ${JSON.stringify(r.codes)}, wanted exactly [${want.only}]`);
  if (want.tiers && JSON.stringify(r.tiers) !== JSON.stringify(want.tiers)) problems.push(`tiers ${JSON.stringify(r.tiers)}, wanted ${JSON.stringify(want.tiers)}`);
  if (want.primary && r.primaryCode !== want.primary) problems.push(`primaryCode ${r.primaryCode}, wanted ${want.primary}`);
  if (want.absent && r.codes.includes(want.absent)) problems.push(`codes ${JSON.stringify(r.codes)}, wanted without ${want.absent}`);
  if (problems.length) { failed++; console.log(`✗ ${name} — ${problems.join(' ; ')}${r.details.length ? ' — ' + r.details.map((d) => d.code + ': ' + d.message).join(' | ') : ''}`); }
  else { pass++; if (want.verdict === 'reject') (want.code || want.only) && refusals.add(want.code || want.only); else accepts++; }
}
const ok = (name, buf, result, extra = {}, keys = []) => check(name, buf, { verdict: 'accept', result, ...extra }, keys);
const no = (name, buf, only) => check(name, buf, { verdict: 'reject', only });
const noAmong = (name, buf, code) => check(name, buf, { verdict: 'reject', code });
const edit = (buf, from, to) => { const s = buf.toString('latin1'); if (!s.includes(from)) throw new Error(`edit: ${from} not found`); return Buffer.from(s.replace(from, to), 'latin1'); };
const wrap = (inner) => Buffer.concat([Buffer.from('{"_type":"https://in-toto.io/Statement/v1","x":'), inner, Buffer.from('}')]);

// ── accepted statements (the controls every refusal below is paired with) ──
ok('base: one caught row, two clean rows', build(), 'fail', { tiers: ['unattested', 'unattested', 'unattested'] });
ok('base, key pinned: every substrate row attested', build(), 'fail', { tiers: ['attested', 'attested', 'attested'] }, KEYS1);
ok('base, another key pinned: unattested, result unmoved', build(), 'fail', { tiers: ['unattested', 'unattested', 'unattested'] }, KEYS2);
ok('all clean, substrate, intercepted', allClean(), 'pass', { tiers: ['attested', 'attested', 'attested'] }, KEYS1);
ok('artifact only, no record, no runEntropy', artifactOnly(), 'pass_indirect', { tiers: ['declared', 'declared', 'declared'] }, KEYS1);
ok('artifact only: digest spelling is not constrained without a substrate row', artifactOnly({ env: (e) => { delete e.runEntropy; e.substrate.digest.sha256 = 'ABC'; e.catchPolicy.digest.sha256 = 'not-hex'; } }), 'pass_indirect');
ok('a class disclosed out of scope', build({ result: 'fail', coverage: { assessedClasses: ['CO'], outOfScope: { FS: 'no filesystem vantage' }, routedElsewhere: {} }, rows: () => [caughtRow(), row('CO-EXFIL-2')] }), 'fail');
ok('all clean with a disclosed gap', allClean({ result: 'degraded', coverage: { assessedClasses: ['CO'], outOfScope: {}, routedElsewhere: { FS: 'assessed by another run' } }, rows: () => ['CO-EXFIL-1', 'CO-EXFIL-2'].map((id) => row(id, { observationRefs: [0, 1] })) }), 'degraded');
ok('fully skipped run: every class disclosed, zero rows', build({ result: 'degraded', env: (e) => { delete e.runEntropy; }, records: () => [], coverage: { assessedClasses: [], outOfScope: { CO: 'skipped', FS: 'skipped' }, routedElsewhere: {} }, rows: () => [] }), 'degraded');
ok('a reconstructed clean row covered by an examination', build({ result: 'pass_indirect', records: (c) => [arming(c), sealed(c, { aeeObservedAttacks: [] }), examination()], rows: () => [row('CO-EXFIL-1', { observationRefs: [0, 1] }), row('CO-EXFIL-2', { observationRefs: [0, 1] }), row('FS-WRITE-1', { method: 'reconstructed', observationRefs: [2] })] }), 'pass_indirect');
ok('a caught reconstructed row covered by an examination', build({ records: (c) => [examination(), arming(c), sealed(c, { aeeObservedAttacks: [] })], rows: () => [caughtRow({ method: 'reconstructed', attribution: 'paired', observationRefs: [0] }), row('CO-EXFIL-2'), row('FS-WRITE-1')] }), 'fail');
ok('an unrecognized kind, carried and unreferenced', build({ records: (c) => [interception(), arming(c), sealed(c), { p: { aeeKind: 'hardware-quote', aeeMethod: 'intercepted' } }] }), 'fail');
ok('a moat-drop and an uncommitted-observation, carried and unreferenced', build({ records: (c) => [interception(), arming(c), sealed(c), { p: { aeeKind: 'moat-drop' } }, { p: { aeeKind: 'uncommitted-observation', aeePayloadCommitment: [H('x')] } }] }), 'fail');
ok('an opaque record (not +json), carried and unreferenced', build({ records: (c) => [interception(), arming(c), sealed(c), { raw: Buffer.from('not json at all'), type: 'application/octet-stream' }] }), 'fail');
ok('predicate-level evidenceTier and aee* members are ignored', build({ statement: (s) => { s.predicate.evidenceTier = 'attested'; s.predicate.aeeAnything = { deep: true }; } }), 'fail', { tiers: ['unattested', 'unattested', 'unattested'] });
ok('producer territory inside a payload is inert', build({ records: (c) => [interception({ confidence: 'low', strength: 0 }), arming(c, { vendor: { rank: 3 } }), sealed(c)] }), 'fail');
ok('issuedAt with -00:00 and a fraction', build({ issuedAt: '2026-06-23T16:08:07.250-00:00' }), 'fail');
ok('a fail-closed artifact row forces fail and stays valid', build({ rows: () => [caughtRow(), row('CO-EXFIL-2'), { attackId: 'FS-WRITE-1', containmentObserved: 'something_else', basis: 'substrate_observed', method: 'intercepted', attribution: 'paired', actualLayer: 'x' }] }), 'fail');
ok('a missing attribution forces fail', allClean({ result: 'fail', rows: () => IDS.map((id, i) => { const r = row(id, { observationRefs: [0, 1] }); if (i === 2) delete r.attribution; return r; }) }), 'fail');
ok('two arming and two sealed records, all valid', allClean({ records: (c) => [arming(c), sealed(c, { aeeObservedAttacks: [] }), arming(c, { armedAt: '2026-06-23T16:00:01Z' }), sealed(c, { aeeObservedAttacks: [], aeeDropCount: 2, aeeDropBound: 5 })] }), 'pass');
ok('a drop count within its declared bound', allClean({ records: (c) => [arming(c), sealed(c, { aeeObservedAttacks: [], aeeDropCount: 3, aeeDropBound: 3 })] }), 'pass');
ok('a run-sequence genesis', allClean({ records: (c) => [arming(c, { aeeRunSeq: 1, aeeChainScope: ['subject'] }), sealed(c, { aeeObservedAttacks: [] })] }), 'pass');
ok('a run-sequence successor', allClean({ records: (c) => [arming(c, { aeeRunSeq: 7, aeePrevRunBinding: H('prev'), aeeChainScope: ['corpus', 'networkPosture', 'subject'], aeeBindingVersion: '2' }), sealed(c, { aeeObservedAttacks: [] })] }), 'pass');
ok('an arming record of another run, carried and unreferenced', allClean({ records: (c) => [arming(c), sealed(c, { aeeObservedAttacks: [] }), arming(c, { aeeRunBinding: H('other run'), aeeAssessedAttacks: [] })] }), 'pass');
ok('an unrecognized aee* member on an extra, unreferenced arming record', allClean({ records: (c) => [arming(c), sealed(c, { aeeObservedAttacks: [] }), arming(c, { aeeFuture: 1, armedAt: '2026-06-23T16:00:02Z' })] }), 'pass');
ok('a pinned row whose interception is shared with a second caught row', build({ rows: () => [caughtRow(), row('CO-EXFIL-2', { containmentObserved: 'egress_captured', actualLayer: 'none', observationRefs: [0] }), row('FS-WRITE-1')], records: (c) => [interception(), arming(c), sealed(c, { aeeObservedAttacks: ['CO-EXFIL-1', 'CO-EXFIL-2'] })] }), 'fail');
ok('depth exactly 128', build({ statement: (s) => { let v = 1; for (let k = 0; k < 126; k++) v = [v]; s.predicate.deep = v; } }), 'fail');
ok('escapes: a surrogate pair, a control escape, U+0000', build({ statement: (s) => { s.predicate.note = 'a\u0000b😀\u001f'; } }), 'fail');
ok('exponent notation, fractions and the largest safe integer are legal JSON numbers', edit(build({ statement: (s) => { s.predicate.n = 111; } }), '"n":111', '"n":[1.5e15,-0,1E2,0.1e-3,9007199254740991,-9007199254740991,9.007199254740991e15]'), 'fail');
ok('earlier member spellings are unknown members, and ignored', build({ statement: (s) => { s.predicate.does_not_assert = ['x']; s.predicate.interceptRecords = []; s.predicate.attackResults[0].interceptRefs = [0]; } }), 'fail');
ok('a class listed twice in assessedClasses is one class', allClean({ coverage: { assessedClasses: ['CO', 'CO', 'FS'], outOfScope: {}, routedElsewhere: {} } }), 'pass');
ok('strings are kept as written: a leading U+FEFF, escapes beside raw multi-byte characters', artifactOnly({ manifest: { classes: { CO: ['CO-EXFIL-1', 'CO-EXFIL-2'], FS: ['FS-WRITE-1'] }, note: BOM + 'é' + String.fromCharCode(1) + '日本😀"\\/x' + LS } }), 'pass_indirect');
ok('one record: the root is its leaf hash', artifactOnly({ records: () => [examination()] }), 'pass_indirect');
ok('a seven-leaf tree', allClean({ records: (c) => [arming(c), sealed(c, { aeeObservedAttacks: [] }), ...[1, 2, 3, 4, 5].map((k) => ({ p: { aeeKind: 'hardware-quote', n: k } }))] }), 'pass');
ok('a second arming record of this run declaring binding version 1, unreferenced: it covers nothing and violates nothing', allClean({ records: (c) => [arming(c), sealed(c, { aeeObservedAttacks: [] }), arming(c, { aeeBindingVersion: '1', armedAt: '2026-06-23T16:00:02Z' })] }), 'pass');
ok('a second arming record of this run with a run-sequence fault, unreferenced: it covers nothing and violates nothing', allClean({ records: (c) => [arming(c), sealed(c, { aeeObservedAttacks: [] }), arming(c, { aeeRunSeq: 0, aeeChainScope: ['subject'], armedAt: '2026-06-23T16:00:02Z' })] }), 'pass');
ok('an interception without aeeMethod, resolved only by an artifact row: it covers nothing and violates nothing', build({ records: (c) => [interception({ aeeMethod: undefined }), arming(c), sealed(c)], rows: () => [caughtRow({ basis: 'artifact', attribution: 'paired' }), row('CO-EXFIL-2'), row('FS-WRITE-1')] }), 'fail');
ok('a referenced moat-drop beside the covering interception: the value of its aeeMethod is not read', build({ records: (c) => [interception(), arming(c), sealed(c), { p: { aeeKind: 'moat-drop', aeeMethod: 'seen-at-the-kernel' } }], rows: () => [caughtRow({ observationRefs: [0, 3] }), row('CO-EXFIL-2'), row('FS-WRITE-1')] }), 'fail', { tiers: ['attested', 'attested', 'attested'] }, KEYS1);
ok('an intercepted row also resolving an examination that covers nothing: that record is out of the method cap', allClean({ records: (c) => [arming(c), sealed(c, { aeeObservedAttacks: [] }), examination({ aeeFuture: 1 })], rows: () => IDS.map((id, i) => row(id, { observationRefs: i === 2 ? [0, 1, 2] : [0, 1] })) }), 'pass');
ok('a seal of another run, carried, whose observed set recomputes', allClean({ records: (c) => [arming(c), sealed(c, { aeeObservedAttacks: [] }), sealed(c, { aeeRunBinding: H('other run'), aeeObservedAttacks: [] })] }), 'pass');

// ── the JSON layer ──
no('duplicate member, top level', edit(build(), '{"_type"', '{"_type":"x","_type"'), 'JSON_DUPLICATE_MEMBER');
no('duplicate member, deep in producer territory', edit(build({ statement: (s) => { s.predicate.vendor = { a: { b: 1 } }; } }), '{"b":1}', '{"b":1,"b":2}'), 'JSON_DUPLICATE_MEMBER');
no('duplicate member spelled with an escape', edit(build(), '{"_type"', '{"_typ\\u0065":"x","_type"'), 'JSON_DUPLICATE_MEMBER');
no('overlong UTF-8', edit(build({ statement: (s) => { s.predicate.note = 'MARK'; } }), 'MARK', '\xC0\x80'), 'JSON_INVALID_UTF8');
no('a surrogate encoded in UTF-8', edit(build({ statement: (s) => { s.predicate.note = 'MARK'; } }), 'MARK', '\xED\xA0\x80'), 'JSON_INVALID_UTF8');
no('truncated UTF-8 at the end', Buffer.concat([build(), Buffer.from([0xE2, 0x82])]), 'JSON_INVALID_UTF8');
no('an unpaired low surrogate escape', edit(build({ statement: (s) => { s.predicate.note = 'MARK'; } }), 'MARK', '\\uDC00'), 'JSON_STRING_ILL_FORMED');
no('a high surrogate escape followed by a letter', edit(build({ statement: (s) => { s.predicate.note = 'MARK'; } }), 'MARK', '\\uD83Dx'), 'JSON_STRING_ILL_FORMED');
no('a high surrogate escape followed by a high surrogate escape', edit(build({ statement: (s) => { s.predicate.note = 'MARK'; } }), 'MARK', '\\uD83D\\uD83D'), 'JSON_STRING_ILL_FORMED');
no('a raw control character in a string', edit(build({ statement: (s) => { s.predicate.note = 'MARK'; } }), 'MARK', '\x01'), 'JSON_STRING_ILL_FORMED');
no('a \\u escape with a sign', edit(build({ statement: (s) => { s.predicate.note = 'MARK'; } }), 'MARK', '\\u+041'), 'JSON_SYNTAX');
no('a noncharacter, raw (U+FFFE)', edit(build({ statement: (s) => { s.predicate.note = 'MARK'; } }), 'MARK', '\xEF\xBF\xBE'), 'JSON_NONCHARACTER');
no('a noncharacter, escaped (U+FDD0), in a member name', edit(build({ statement: (s) => { s.predicate.MARK = 1; } }), 'MARK', '\\uFDD0'), 'JSON_NONCHARACTER');
no('a supplementary noncharacter by surrogate escapes (U+1FFFE)', edit(build({ statement: (s) => { s.predicate.note = 'MARK'; } }), 'MARK', '\\uD83F\\uDFFE'), 'JSON_NONCHARACTER');
no('depth 129', build({ statement: (s) => { let v = 1; for (let k = 0; k < 127; k++) v = [v]; s.predicate.deep = v; } }), 'JSON_DEPTH_EXCEEDED');
no('an integer at 2^53', edit(build({ statement: (s) => { s.predicate.n = 111; } }), '"n":111', '"n":9007199254740992'), 'JSON_NUMBER_OUT_OF_RANGE');
no('a negative integer at -2^53', edit(build({ statement: (s) => { s.predicate.n = 111; } }), '"n":111', '"n":-9007199254740992'), 'JSON_NUMBER_OUT_OF_RANGE');
no('a number beyond the double range', edit(build({ statement: (s) => { s.predicate.n = 111; } }), '"n":111', '"n":1e999'), 'JSON_NUMBER_OUT_OF_RANGE');
no('2^53 written with an exponent', edit(build({ statement: (s) => { s.predicate.n = 111; } }), '"n":111', '"n":9.007199254740992e15'), 'JSON_NUMBER_OUT_OF_RANGE');
no('2^53 written with a fraction', edit(build({ statement: (s) => { s.predicate.n = 111; } }), '"n":111', '"n":9007199254740992.0'), 'JSON_NUMBER_OUT_OF_RANGE');
no('an integer above 2^53 written 1e16', edit(build({ statement: (s) => { s.predicate.n = 111; } }), '"n":111', '"n":-1e16'), 'JSON_NUMBER_OUT_OF_RANGE');
no('a large number that is an integer by value', edit(build({ statement: (s) => { s.predicate.n = 111; } }), '"n":111', '"n":1.5e300'), 'JSON_NUMBER_OUT_OF_RANGE');
no('a leading zero', edit(build({ statement: (s) => { s.predicate.n = 111; } }), '"n":111', '"n":0111'), 'JSON_SYNTAX');
no('content after the statement', Buffer.concat([build(), Buffer.from(' {}')]), 'JSON_SYNTAX');
no('a byte order mark', Buffer.concat([Buffer.from([0xEF, 0xBB, 0xBF]), build()]), 'JSON_SYNTAX');
no('a top-level array', Buffer.from('[]'), 'JSON_TOP_LEVEL_NOT_OBJECT');
no('an empty input', Buffer.alloc(0), 'JSON_SYNTAX');
no('a trailing comma', wrap(Buffer.from('[1,]')), 'JSON_SYNTAX');

// ── statement shape ──
no('another statement type', build({ statement: (s) => { s._type = 'https://in-toto.io/Statement/v0.1'; } }), 'STATEMENT_TYPE_INVALID');
no('predicate type v0.6 (retired, no alias)', build({ statement: (s) => { s.predicateType = s.predicateType.replace('v0.7', 'v0.6'); } }), 'PREDICATE_TYPE_UNSUPPORTED');
no('zero subjects', build({ statement: (s) => { s.subject = []; } }), 'SUBJECT_COUNT_INVALID');
no('two subjects', artifactOnly({ statement: (s) => { s.subject.push(clone(s.subject[0])); } }), 'SUBJECT_COUNT_INVALID');
no('a null subject entry, no substrate row', artifactOnly({ statement: (s) => { s.subject = [null]; } }), 'SUBJECT_DIGEST_INVALID');
no('a null subject entry, substrate rows', build({ statement: (s) => { s.subject = [null]; } }), 'SUBJECT_DIGEST_INVALID');
no('a subject entry without a digest', artifactOnly({ statement: (s) => { s.subject = [{ name: 'artifact' }]; } }), 'SUBJECT_DIGEST_INVALID');
no('no predicate', build({ statement: (s) => { delete s.predicate; } }), 'PREDICATE_INVALID');
no('no result', build({ statement: (s) => { delete s.predicate.result; } }), 'RESULT_MISSING');
no('issuedAt absent', build({ statement: (s) => { delete s.predicate.issuedAt; } }), 'ISSUED_AT_INVALID');
no('issuedAt with a lowercase t', build({ issuedAt: '2026-06-23t16:08:07Z' }), 'ISSUED_AT_INVALID');
no('issuedAt with a lowercase z', build({ issuedAt: '2026-06-23T16:08:07z' }), 'ISSUED_AT_INVALID');
no('issuedAt with a non-zero offset', build({ issuedAt: '2026-06-23T21:08:07+05:00' }), 'ISSUED_AT_INVALID');
no('issuedAt on the thirtieth of February', build({ issuedAt: '2026-02-30T16:08:07Z' }), 'ISSUED_AT_INVALID');
no('issuedAt without seconds', build({ issuedAt: '2026-06-23T16:08Z' }), 'ISSUED_AT_INVALID');
no('doesNotAssert as a string', build({ statement: (s) => { s.predicate.doesNotAssert = 'nothing'; } }), 'DOES_NOT_ASSERT_MISTYPED');
noAmong('no observationEnvironment', build({ statement: (s) => { delete s.predicate.observationEnvironment; } }), 'ENVIRONMENT_INVALID');

// ── observationEnvironment ──
const E = (s) => s.predicate.observationEnvironment;
no('a posture that is not a string', artifactOnly({ statement: (s) => { E(s).networkPosture.posture = 7; } }), 'NETWORK_POSTURE_INVALID');
no('no networkPosture', artifactOnly({ statement: (s) => { delete E(s).networkPosture; } }), 'NETWORK_POSTURE_INVALID');
no('a substrate without a digest', artifactOnly({ statement: (s) => { delete E(s).substrate.digest; } }), 'ENVIRONMENT_SUBSTRATE_INVALID');
no('no catchPolicy', artifactOnly({ statement: (s) => { delete E(s).catchPolicy; } }), 'ENVIRONMENT_CATCH_POLICY_INVALID');
no('a corpus without a digest', artifactOnly({ statement: (s) => { delete E(s).corpus.digest; } }), 'CORPUS_INVALID');
noAmong('a corpus without a manifest', artifactOnly({ statement: (s) => { delete E(s).corpus.manifest; } }), 'MANIFEST_MALFORMED');
noAmong('a class holding something that is not a string', artifactOnly({ manifest: { classes: { CO: ['CO-EXFIL-1', 'CO-EXFIL-2', 7], FS: ['FS-WRITE-1'] } } }), 'MANIFEST_MALFORMED');
noAmong('no observationVocabulary', artifactOnly({ statement: (s) => { delete E(s).observationVocabulary; } }), 'VOCABULARY_MALFORMED');
no('coverage without outOfScope', artifactOnly({ statement: (s) => { delete s.predicate.coverage.outOfScope; } }), 'COVERAGE_MALFORMED');
no('no attackResults', artifactOnly({ statement: (s) => { delete s.predicate.attackResults; } }), 'ATTACK_RESULTS_MALFORMED');
no('an actualLayer that is not a string', artifactOnly({ statement: (s) => { s.predicate.attackResults[0].actualLayer = null; } }), 'ROW_ACTUAL_LAYER_MISSING');
no('doesNotAssert carried as null', artifactOnly({ statement: (s) => { s.predicate.doesNotAssert = null; } }), 'DOES_NOT_ASSERT_MISTYPED');
no('a second 60 that does not close a day', build({ issuedAt: '2026-06-23T16:08:60Z' }), 'ISSUED_AT_INVALID');
ok('a leap second closing a day', build({ issuedAt: '2026-06-30T23:59:60Z' }), 'fail');
ok('an empty observationRecords and no batchRoot', artifactOnly({ statement: (s) => { s.predicate.observationRecords = []; } }), 'pass_indirect');
ok('a reference written -0 is index 0', edit(build(), '"observationRefs":[0]', '"observationRefs":[-0]'), 'fail');
ok('an index listed twice in observationRefs', build({ rows: () => [caughtRow({ observationRefs: [0, 0] }), row('CO-EXFIL-2'), row('FS-WRITE-1')] }), 'fail');
no('an unregistered posture', build({ env: (e) => { e.networkPosture.posture = 'open'; } }), 'NETWORK_POSTURE_INVALID');
no('posture absent', build({ env: (e) => { delete e.networkPosture.posture; } }), 'NETWORK_POSTURE_INVALID');
no('labels not sorted', build({ vocab: { labels: ['no_egress', 'egress_captured'], caught: ['egress_captured'] } }), 'VOCABULARY_MALFORMED');
no('labels with a duplicate', build({ vocab: { labels: ['egress_captured', 'egress_captured', 'no_egress'], caught: ['egress_captured'] } }), 'VOCABULARY_MALFORMED');
no('caught not a subset of labels', build({ vocab: { labels: ['egress_captured', 'no_egress'], caught: ['blocked'] } }), 'VOCABULARY_MALFORMED');
no('a supplementary-plane label', build({ vocab: { labels: ['egress_captured', 'no_egress', '😀'], caught: ['egress_captured'] } }), 'VOCABULARY_MALFORMED');
no('the caught set narrowed after the digest', build({ statement: (s) => { s.predicate.result = 'pass'; s.predicate.observationEnvironment.observationVocabulary.caught = []; } }), 'ROW_ACTUAL_LAYER_NOT_NONE');
no('a vocabulary digest that does not re-derive', artifactOnly({ statement: (s) => { s.predicate.observationEnvironment.observationVocabulary.digest.sha256 = H('x'); } }), 'VOCABULARY_DIGEST_MISMATCH');
no('a manifest edited after its digest', artifactOnly({ statement: (s) => { s.predicate.observationEnvironment.corpus.manifest.note = 'edited'; } }), 'CORPUS_DIGEST_MISMATCH');
no('expectedPayloads edited after the digest', artifactOnly({ statement: (s) => { s.predicate.observationEnvironment.corpus.manifest.expectedPayloads['CO-EXFIL-1'] = [H('other')]; } }), 'CORPUS_DIGEST_MISMATCH');
no('a manifest with no class', artifactOnly({ manifest: { classes: {} }, coverage: { assessedClasses: [], outOfScope: {}, routedElsewhere: {} }, rows: () => [], result: 'pass' }), 'MANIFEST_DECLARES_NO_ATTACK');
no('a manifest whose only class is empty', artifactOnly({ manifest: { classes: { CO: [] } }, coverage: { assessedClasses: ['CO'], outOfScope: {}, routedElsewhere: {} }, rows: () => [], result: 'pass' }), 'MANIFEST_DECLARES_NO_ATTACK');
noAmong('an attack under two classes', artifactOnly({ manifest: { classes: { CO: ['CO-EXFIL-1', 'CO-EXFIL-2'], FS: ['FS-WRITE-1', 'CO-EXFIL-1'] } } }), 'MANIFEST_ATTACK_IN_MULTIPLE_CLASSES');
noAmong('classes as an array', artifactOnly({ manifest: { classes: ['CO'] } }), 'MANIFEST_MALFORMED');
no('expectedPayloads for an undeclared attack', artifactOnly({ manifest: { classes: { CO: ['CO-EXFIL-1', 'CO-EXFIL-2'], FS: ['FS-WRITE-1'] }, expectedPayloads: { 'XX-1': [H('a')] } } }), 'EXPECTED_PAYLOADS_MALFORMED');
no('expectedPayloads with an empty array', artifactOnly({ manifest: { classes: { CO: ['CO-EXFIL-1', 'CO-EXFIL-2'], FS: ['FS-WRITE-1'] }, expectedPayloads: { 'CO-EXFIL-1': [] } } }), 'EXPECTED_PAYLOADS_MALFORMED');
no('expectedPayloads in uppercase hex', artifactOnly({ manifest: { classes: { CO: ['CO-EXFIL-1', 'CO-EXFIL-2'], FS: ['FS-WRITE-1'] }, expectedPayloads: { 'CO-EXFIL-1': [H('a').toUpperCase()] } } }), 'EXPECTED_PAYLOADS_MALFORMED');
no('expectedPayloads not sorted', artifactOnly({ manifest: { classes: { CO: ['CO-EXFIL-1', 'CO-EXFIL-2'], FS: ['FS-WRITE-1'] }, expectedPayloads: { 'CO-EXFIL-1': [H('a'), H('b')].sort().reverse() } } }), 'EXPECTED_PAYLOADS_MALFORMED');

// ── coverage ──
no('a class both assessed and out of scope', build({ coverage: { assessedClasses: ['CO', 'FS'], outOfScope: { FS: 'x' }, routedElsewhere: {} } }), 'COVERAGE_PARTITION_INVALID');
no('a class both out of scope and routed elsewhere', artifactOnly({ coverage: { assessedClasses: ['CO'], outOfScope: { FS: 'x' }, routedElsewhere: { FS: 'y' } } }), 'COVERAGE_PARTITION_INVALID');
no('a manifest class in none of the three', artifactOnly({ coverage: { assessedClasses: ['CO'], outOfScope: {}, routedElsewhere: {} } }), 'COVERAGE_PARTITION_INVALID');
no('coverage naming a class the manifest does not declare', artifactOnly({ coverage: { assessedClasses: ['CO', 'FS', 'ZZ'], outOfScope: {}, routedElsewhere: {} } }), 'COVERAGE_PARTITION_INVALID');
no('a reason that is not a string', artifactOnly({ coverage: { assessedClasses: ['CO'], outOfScope: { FS: 1 }, routedElsewhere: {} } }), 'COVERAGE_MALFORMED');
no('an assessed attack with no row', artifactOnly({ rows: () => ['CO-EXFIL-1', 'CO-EXFIL-2'].map((id) => ({ attackId: id, containmentObserved: 'no_egress', basis: 'artifact', method: 'intercepted', attribution: 'paired', actualLayer: 'none' })) }), 'COVERAGE_INTEGRITY_MISMATCH');
no('a row for an attack of a class disclosed out of scope', artifactOnly({ result: 'degraded', coverage: { assessedClasses: ['CO'], outOfScope: { FS: 'x' }, routedElsewhere: {} } }), 'COVERAGE_INTEGRITY_MISMATCH');

// ── rows ──
no('two rows for one attack', artifactOnly({ statement: (s) => { s.predicate.attackResults[2].attackId = 'CO-EXFIL-1'; } }), 'ROW_ATTACK_ID_DUPLICATE');
no('a row for an attack the manifest does not declare', artifactOnly({ statement: (s) => { s.predicate.attackResults[2].attackId = 'XX-1'; } }), 'ROW_ATTACK_ID_NOT_IN_MANIFEST');
no('a row without actualLayer', artifactOnly({ statement: (s) => { delete s.predicate.attackResults[0].actualLayer; } }), 'ROW_ACTUAL_LAYER_MISSING');
no('a clean row whose actualLayer is not none', artifactOnly({ statement: (s) => { s.predicate.attackResults[0].actualLayer = 'policy.x'; } }), 'ROW_ACTUAL_LAYER_NOT_NONE');
no('an out-of-range reference on an artifact row', artifactOnly({ statement: (s) => { s.predicate.attackResults[0].observationRefs = [0]; } }), 'ROW_OBSERVATION_REF_INVALID');
no('an out-of-range reference on a substrate row', build({ rows: () => [caughtRow({ observationRefs: [0, 3] }), row('CO-EXFIL-2'), row('FS-WRITE-1')] }), 'ROW_OBSERVATION_REF_INVALID');
no('a negative reference', build({ rows: () => [caughtRow({ observationRefs: [-1] }), row('CO-EXFIL-2'), row('FS-WRITE-1')] }), 'ROW_OBSERVATION_REF_INVALID');
no('a reference written as 0.0', edit(build(), '"observationRefs":[0]', '"observationRefs":[0.0]'), 'ROW_OBSERVATION_REF_INVALID');
no('a row that is not an object', artifactOnly({ statement: (s) => { s.predicate.attackResults[0] = 'CO-EXFIL-1'; } }), 'ROW_MALFORMED');

// ── the result recompute ──
no('pass carried over a caught row', build({ result: 'pass' }), 'RESULT_MISMATCH');
no('pass carried over artifact clean rows', artifactOnly({ result: 'pass' }), 'RESULT_MISMATCH');
no('pass carried over a disclosed gap', allClean({ result: 'pass', coverage: { assessedClasses: ['CO'], outOfScope: { FS: 'x' }, routedElsewhere: {} }, rows: () => ['CO-EXFIL-1', 'CO-EXFIL-2'].map((id) => row(id, { observationRefs: [0, 1] })) }), 'RESULT_MISMATCH');
no('a result token outside the vocabulary', build({ result: 'FAIL' }), 'RESULT_MISMATCH');
no('fail carried where the predicate reduces to pass', allClean({ result: 'fail' }), 'RESULT_MISMATCH');

// ── run binding and records ──
no('a substrate row and no runEntropy', build({ statement: (s) => { delete s.predicate.observationEnvironment.runEntropy; } }), 'RUN_ENTROPY_MISSING');
no('a substrate row and an uppercase substrate digest', build({ env: (e) => { e.substrate.digest.sha256 = e.substrate.digest.sha256.toUpperCase(); } }), 'RUN_BINDING_DIGEST_INVALID');
no('a substrate row and a short subject digest', build({ env: (e, subj) => { subj[0].digest.sha256 = 'abc123'; } }), 'RUN_BINDING_DIGEST_INVALID');
noAmong('the posture string changed after signing', build({ statement: (s) => { s.predicate.observationEnvironment.networkPosture.posture = 'allowlist'; } }), 'ROW_REF_RUN_BINDING_MISMATCH');
noAmong('a member added to networkPosture after signing', build({ statement: (s) => { s.predicate.observationEnvironment.networkPosture.note = 'x'; } }), 'ROW_REF_RUN_BINDING_MISMATCH');
noAmong('runEntropy replaced after signing', build({ statement: (s) => { s.predicate.observationEnvironment.runEntropy.digest.sha256 = H('another'); } }), 'ROW_REF_RUN_BINDING_MISMATCH');
no('a record that is not a DSSE envelope: no signature', build({ statement: (s) => { s.predicate.observationRecords[0].signatures = []; } }), 'RECORD_ENVELOPE_MALFORMED');
no('a record whose payload is not base64', build({ statement: (s) => { s.predicate.observationRecords[0].payload = '!!!'; } }), 'RECORD_ENVELOPE_MALFORMED');
no('a record whose payload is unpadded base64', build({ statement: (s) => { s.predicate.observationRecords[0].payload = 'e30'; } }), 'RECORD_ENVELOPE_MALFORMED');
no('observationRecords as an object', artifactOnly({ statement: (s) => { s.predicate.observationRecords = {}; } }), 'OBSERVATION_RECORDS_MALFORMED');
no('two byte-identical records', build({ statement: (s) => { s.predicate.observationRecords.push(clone(s.predicate.observationRecords[1])); } }), 'RECORD_DUPLICATE');
no('records and no batchRoot', build({ statement: (s) => { delete s.predicate.batchRoot; } }), 'BATCH_ROOT_MISSING');
no('a batchRoot that does not recompute', build({ statement: (s) => { s.predicate.batchRoot = H('x'); } }), 'BATCH_ROOT_MISMATCH');
no('a batchRoot in uppercase', build({ statement: (s) => { s.predicate.batchRoot = s.predicate.batchRoot.toUpperCase(); } }), 'BATCH_ROOT_MISMATCH');
no('a batchRoot built by duplicating the last leaf', build({ records: (c) => [interception(), arming(c), sealed(c)], statement: (s) => { const L = s.predicate.observationRecords.map((r) => leafOf(r.payloadType, Buffer.from(r.payload, 'base64'))); const n = (a, b) => shaRaw(Buffer.concat([Buffer.from([1]), a, b])); s.predicate.batchRoot = n(n(L[0], L[1]), n(L[2], L[2])).toString('hex'); } }), 'BATCH_ROOT_MISMATCH');
no('a batchRoot with no record', artifactOnly({ statement: (s) => { s.predicate.batchRoot = H('x'); } }), 'BATCH_ROOT_MISMATCH');
no('a substrate row with empty references', build({ rows: () => [caughtRow({ attribution: 'paired', observationRefs: [] }), row('CO-EXFIL-2'), row('FS-WRITE-1')], records: (c) => [arming(c), sealed(c, { aeeObservedAttacks: [] }), arming(c, { armedAt: '2026-06-23T16:00:03Z' })], statement: (s) => { s.predicate.attackResults[1].observationRefs = [0, 1]; s.predicate.attackResults[2].observationRefs = [0, 1]; } }), 'ROW_SUBSTRATE_NO_REFS');
noAmong('a substrate row pointing at a payload with whitespace', build({ records: (c) => [{ raw: Buffer.from(`{ "aeeKind":"interception","aeeMethod":"intercepted","aeePayloadCommitment":["${H('payload-1')}"],"aeeRunBinding":"${c.binding}"}`) }, arming(c), sealed(c)] }), 'ROW_REF_NOT_CANONICAL_JSON');
noAmong('a substrate row pointing at a payload with unsorted members', build({ records: (c) => [{ raw: Buffer.from(`{"aeeRunBinding":"${c.binding}","aeeKind":"interception","aeeMethod":"intercepted","aeePayloadCommitment":["${H('payload-1')}"]}`) }, arming(c), sealed(c)] }), 'ROW_REF_NOT_CANONICAL_JSON');
noAmong('a substrate row pointing at a record whose media type is not +json', build({ records: (c) => [{ ...interception(), type: 'application/json' }, arming(c), sealed(c)] }), 'ROW_REF_NOT_CANONICAL_JSON');
noAmong('a substrate row pointing at a payload with a supplementary-plane member name', build({ records: (c) => [interception({ '😀': 1 }), arming(c), sealed(c)] }), 'ROW_REF_NOT_CANONICAL_JSON');
noAmong('a substrate row pointing at a payload with a duplicate member', build({ records: (c) => [{ raw: Buffer.from(`{"aeeKind":"interception","aeeKind":"interception","aeeMethod":"intercepted","aeePayloadCommitment":["${H('payload-1')}"],"aeeRunBinding":"${c.binding}"}`) }, arming(c), sealed(c)] }), 'ROW_REF_NOT_CANONICAL_JSON');
noAmong('a substrate row pointing at a record without aeeMethod', build({ records: (c) => [interception({ aeeMethod: undefined }), arming(c), sealed(c)] }), 'ROW_REF_RESERVED_MEMBERS_MISSING');
noAmong('a substrate row pointing at a record of another run', build({ records: (c) => [interception({ aeeRunBinding: H('other run') }), arming(c), sealed(c)] }), 'ROW_REF_RUN_BINDING_MISMATCH');
noAmong('a caught intercepted row covered only by run-level records', build({ rows: () => [caughtRow({ attribution: 'paired', observationRefs: [1, 2] }), row('CO-EXFIL-2'), row('FS-WRITE-1')] }), 'ROW_CLASS_MATCH_FAILED');
no('a clean intercepted row with an arming record and no seal', allClean({ rows: () => IDS.map((id, i) => row(id, { observationRefs: i === 0 ? [0] : [0, 1] })) }), 'ROW_CLASS_MATCH_FAILED');
no('a clean intercepted row with a seal and no arming record', allClean({ rows: () => IDS.map((id, i) => row(id, { observationRefs: i === 0 ? [1] : [0, 1] })) }), 'ROW_CLASS_MATCH_FAILED');
no('a reconstructed row with no examination', allClean({ result: 'pass_indirect', rows: () => IDS.map((id, i) => row(id, { observationRefs: [0, 1], ...(i === 2 ? { method: 'reconstructed' } : {}) })) }), 'ROW_CLASS_MATCH_FAILED');
no('an intercepted row over an examination record', allClean({ records: (c) => [arming(c), sealed(c, { aeeObservedAttacks: [] }), examination()], rows: () => IDS.map((id, i) => row(id, { observationRefs: i === 2 ? [0, 1, 2] : [0, 1] })) }), 'ROW_METHOD_EXCEEDS_RECORDS');
noAmong('a caught row over an interception signed reconstructed', build({ records: (c) => [interception({ aeeMethod: 'reconstructed' }), arming(c), sealed(c)] }), 'ROW_METHOD_EXCEEDS_RECORDS');
noAmong('a row covered only by a moat-drop', build({ records: (c) => [{ p: { aeeKind: 'moat-drop', aeeMethod: 'intercepted' } }, arming(c), sealed(c, { aeeObservedAttacks: [] })], rows: () => [caughtRow({ attribution: 'paired' }), row('CO-EXFIL-2'), row('FS-WRITE-1')] }), 'ROW_REFERENCES_NON_COVERING_KIND');
noAmong('a row covered only by an unrecognized kind', build({ records: (c) => [{ p: { aeeKind: 'hardware-quote', aeeMethod: 'intercepted' } }, arming(c), sealed(c, { aeeObservedAttacks: [] })], rows: () => [caughtRow({ attribution: 'paired' }), row('CO-EXFIL-2'), row('FS-WRITE-1')] }), 'ROW_REFERENCES_UNRECOGNIZED_KIND');
noAmong('an arming record declaring binding version 1', allClean({ records: (c) => [arming(c, { aeeBindingVersion: '1' }), sealed(c, { aeeObservedAttacks: [] })] }), 'RECORD_BINDING_VERSION_UNSUPPORTED');
noAmong('an arming record declaring its binding version as the number 2', allClean({ records: (c) => [arming(c, { aeeBindingVersion: 2 }), sealed(c, { aeeObservedAttacks: [] })] }), 'RECORD_BINDING_VERSION_UNSUPPORTED');
check('an arming record built under another construction: reported as a version, not as a digest mismatch', allClean({ records: (c) => [arming(c, { aeeBindingVersion: '1', aeeRunBinding: H('a version 1 digest') }), sealed(c, { aeeObservedAttacks: [] })] }), { verdict: 'reject', code: 'RECORD_BINDING_VERSION_UNSUPPORTED', absent: 'ROW_REF_RUN_BINDING_MISMATCH' });
noAmong('an interception declaring binding version 1', build({ records: (c) => [interception({ aeeBindingVersion: '1' }), arming(c), sealed(c)] }), 'RECORD_BINDING_VERSION_UNSUPPORTED');
noAmong('an interception whose aeeMethod is outside the vocabulary', build({ records: (c) => [interception({ aeeMethod: 'observed' }), arming(c), sealed(c)] }), 'INTERCEPTION_METHOD_OUT_OF_VOCABULARY');
noAmong('a referenced moat-drop without aeeMethod', build({ records: (c) => [interception(), arming(c), sealed(c), { p: { aeeKind: 'moat-drop' } }], rows: () => [caughtRow({ observationRefs: [0, 3] }), row('CO-EXFIL-2'), row('FS-WRITE-1')] }), 'ROW_REF_RESERVED_MEMBERS_MISSING');
noAmong('a referenced moat-drop of another run', build({ records: (c) => [interception(), arming(c), sealed(c), { p: { aeeKind: 'moat-drop', aeeMethod: 'intercepted', aeeRunBinding: H('other run') } }], rows: () => [caughtRow({ observationRefs: [0, 3] }), row('CO-EXFIL-2'), row('FS-WRITE-1')] }), 'ROW_REF_RUN_BINDING_MISMATCH');
noAmong('a row covered by an interception carrying an unrecognized aee* member', build({ records: (c) => [interception({ aeeVersion: 1 }), arming(c), sealed(c)] }), 'RECORD_UNRECOGNIZED_RESERVED_MEMBER');

// ── statement-level coverage requirements ──
no('a clean row pointing at an interception', build({ result: 'fail', rows: () => [caughtRow(), row('CO-EXFIL-2', { observationRefs: [0, 1, 2] }), row('FS-WRITE-1')] }), 'ROW_CLEAN_REFERENCES_INTERCEPTION');
no('an artifact clean row pointing at an interception', build({ result: 'fail', rows: () => [caughtRow(), row('CO-EXFIL-2', { basis: 'artifact', observationRefs: [0] }), row('FS-WRITE-1')] }), 'ROW_CLEAN_REFERENCES_INTERCEPTION');
noAmong('an interception no caught row accounts for', build({ result: 'pass', rows: () => IDS.map((id) => row(id)), records: (c) => [interception(), arming(c), sealed(c, { aeeObservedAttacks: [] })] }), 'INTERCEPTION_NOT_REFERENCED_BY_CAUGHT_ROW');
noAmong('a substrate caught row and no sealed record', build({ records: () => [interception()], rows: () => [caughtRow(), row('CO-EXFIL-2', { basis: 'artifact', observationRefs: undefined }), row('FS-WRITE-1', { basis: 'artifact', observationRefs: undefined })].map((r) => { if (r.observationRefs === undefined) delete r.observationRefs; return r; }) }), 'SEAL_REQUIRED_NONE_VALID');
check('the only seal reports its vantage down: the missing seal is the primary condition', allClean({ records: (c) => [arming(c), sealed(c, { aeeObservedAttacks: [], aeeStillArmed: false })] }), { verdict: 'reject', code: 'SEAL_NOT_STILL_ARMED', primary: 'SEAL_REQUIRED_NONE_VALID' });
no('a seal reporting its vantage down, carried beside a good seal no row points away from', allClean({ records: (c) => [arming(c), sealed(c, { aeeObservedAttacks: [] }), sealed(c, { aeeObservedAttacks: [], aeeStillArmed: false, aeeDropCount: 0, note: 'second' })] }), 'SEAL_NOT_STILL_ARMED');
noAmong('a drop count with no bound', allClean({ records: (c) => [arming(c), sealed(c, { aeeObservedAttacks: [], aeeDropCount: 3 })] }), 'SEAL_DROP_COUNT_EXCEEDED');
noAmong('a drop count above its bound', allClean({ records: (c) => [arming(c), sealed(c, { aeeObservedAttacks: [], aeeDropCount: 6, aeeDropBound: 5 })] }), 'SEAL_DROP_COUNT_EXCEEDED');
noAmong('a seal whose posture digest moved', allClean({ records: (c) => [arming(c), sealed(c, { aeeObservedAttacks: [], aeePostureDigest: H('later posture') })] }), 'SEAL_POSTURE_DIGEST_MISMATCH');
noAmong('a seal without aeeObservedAttacks', allClean({ records: (c) => [arming(c), sealed(c, { aeeObservedAttacks: undefined })] }), 'SEAL_OBSERVED_ATTACKS_INVALID');
noAmong('a seal whose aeeStillArmed is a string', allClean({ records: (c) => [arming(c), sealed(c, { aeeObservedAttacks: [], aeeStillArmed: 'true' })] }), 'SEAL_MEMBER_INVALID');
noAmong('a seal signed reconstructed', allClean({ records: (c) => [arming(c), sealed(c, { aeeObservedAttacks: [], aeeMethod: 'reconstructed' })] }), 'SEAL_METHOD_INVALID');
noAmong('a seal committing to another record set', build({ records: (c) => [interception(), arming(c), sealed(c, { aeeObservedSet: H('another set') })] }), 'SEAL_OBSERVED_SET_MISMATCH');
noAmong('an interception deleted after the seal was signed', build({ result: 'pass', statement: (s) => { const p = s.predicate; p.observationRecords.shift(); p.attackResults = IDS.map((id) => row(id, { observationRefs: [0, 1] })); p.batchRoot = mth(p.observationRecords.map((r) => leafOf(r.payloadType, Buffer.from(r.payload, 'base64')))).toString('hex'); }, records: (c) => [interception(), arming(c), sealed(c, { aeeObservedAttacks: [] })] }), 'SEAL_OBSERVED_SET_MISMATCH');
no('a seal naming an attack whose row is clean', allClean({ records: (c) => [arming(c), sealed(c, { aeeObservedAttacks: ['FS-WRITE-1'] })] }), 'SEAL_OBSERVED_ATTACK_WITHOUT_CAUGHT_ROW');
noAmong('a seal naming an attack the manifest does not declare', allClean({ records: (c) => [arming(c), sealed(c, { aeeObservedAttacks: ['XX-1'] })] }), 'SEAL_OBSERVED_ATTACKS_INVALID');
no('an arming record that declared fewer attacks than are now assessed', allClean({ records: (c) => [arming(c, { aeeAssessedAttacks: ['CO-EXFIL-1', 'CO-EXFIL-2'] }), sealed(c, { aeeObservedAttacks: [] })] }), 'ARMING_ASSESSED_ATTACKS_NOT_SUPERSET');
noAmong('an arming record armed after issuedAt', allClean({ records: (c) => [arming(c, { armedAt: '2026-06-23T16:08:08Z' }), sealed(c, { aeeObservedAttacks: [] })] }), 'ARMING_ARMED_AT_INVALID');
noAmong('an arming record armed a fraction of a second after issuedAt', allClean({ issuedAt: '2026-06-23T16:08:07.5Z', records: (c) => [arming(c, { armedAt: '2026-06-23T16:08:07.51Z' }), sealed(c, { aeeObservedAttacks: [] })] }), 'ARMING_ARMED_AT_INVALID');
noAmong('an arming record whose armedAt has a lowercase z', allClean({ records: (c) => [arming(c, { armedAt: '2026-06-23T16:00:00z' }), sealed(c, { aeeObservedAttacks: [] })] }), 'ARMING_ARMED_AT_INVALID');
noAmong('an arming record without armedAt', allClean({ records: (c) => [arming(c, { armedAt: undefined }), sealed(c, { aeeObservedAttacks: [] })] }), 'ARMING_ARMED_AT_INVALID');
noAmong('an arming record whose posture digest is not the pinned one', allClean({ records: (c) => [arming(c, { aeePostureDigest: H('x') }), sealed(c, { aeeObservedAttacks: [] })] }), 'ARMING_POSTURE_DIGEST_MISMATCH');
noAmong('an arming record signed reconstructed', allClean({ records: (c) => [arming(c, { aeeMethod: 'reconstructed' }), sealed(c, { aeeObservedAttacks: [] })] }), 'ARMING_METHOD_INVALID');
noAmong('assessed attacks not sorted', allClean({ records: (c) => [arming(c, { aeeAssessedAttacks: [...IDS].reverse() }), sealed(c, { aeeObservedAttacks: [] })] }), 'ARMING_ASSESSED_ATTACKS_INVALID');
noAmong('a run sequence of 1 with a predecessor', allClean({ records: (c) => [arming(c, { aeeRunSeq: 1, aeePrevRunBinding: H('p'), aeeChainScope: ['subject'] }), sealed(c, { aeeObservedAttacks: [] })] }), 'ARMING_RUN_SEQUENCE_INVALID');
noAmong('a run sequence of 2 without a predecessor', allClean({ records: (c) => [arming(c, { aeeRunSeq: 2, aeeChainScope: ['subject'] }), sealed(c, { aeeObservedAttacks: [] })] }), 'ARMING_RUN_SEQUENCE_INVALID');
noAmong('a run sequence without its scope', allClean({ records: (c) => [arming(c, { aeeRunSeq: 1 }), sealed(c, { aeeObservedAttacks: [] })] }), 'ARMING_RUN_SEQUENCE_INVALID');
noAmong('a chain scope without a run sequence', allClean({ records: (c) => [arming(c, { aeeChainScope: ['subject'] }), sealed(c, { aeeObservedAttacks: [] })] }), 'ARMING_RUN_SEQUENCE_INVALID');
noAmong('a chain scope out of order', allClean({ records: (c) => [arming(c, { aeeRunSeq: 1, aeeChainScope: ['subject', 'corpus'] }), sealed(c, { aeeObservedAttacks: [] })] }), 'ARMING_RUN_SEQUENCE_INVALID');
noAmong('a chain scope with an unregistered token', allClean({ records: (c) => [arming(c, { aeeRunSeq: 1, aeeChainScope: ['tenant'] }), sealed(c, { aeeObservedAttacks: [] })] }), 'ARMING_RUN_SEQUENCE_INVALID');
noAmong('a run sequence of zero', allClean({ records: (c) => [arming(c, { aeeRunSeq: 0, aeeChainScope: ['subject'] }), sealed(c, { aeeObservedAttacks: [] })] }), 'ARMING_RUN_SEQUENCE_INVALID');
no('an examination signed intercepted, bound to this run and unreferenced', allClean({ records: (c) => [arming(c), sealed(c, { aeeObservedAttacks: [] }), examination({ aeeMethod: 'intercepted' })] }), 'EXAMINATION_METHOD_INVALID');
noAmong('an interception with an empty commitment', build({ records: (c) => [interception({ aeePayloadCommitment: [] }), arming(c), sealed(c)] }), 'INTERCEPTION_COMMITMENT_INVALID');
noAmong('an interception with an uppercase commitment', build({ records: (c) => [interception({ aeePayloadCommitment: [H('payload-1').toUpperCase()] }), arming(c), sealed(c)] }), 'INTERCEPTION_COMMITMENT_INVALID');
check('the only seal carries an unrecognized aee* member: the missing seal is the primary condition', allClean({ records: (c) => [arming(c), sealed(c, { aeeObservedAttacks: [], aeeNewThing: true })] }), { verdict: 'reject', code: 'RECORD_UNRECOGNIZED_RESERVED_MEMBER', primary: 'SEAL_REQUIRED_NONE_VALID' });
check('the only seal carries an unrecognized aee* member, every row caught: the ground is reported beside the missing seal', build({ records: (c) => [interception(), sealed(c, { aeeObservedAttacks: ['CO-EXFIL-1', 'CO-EXFIL-2', 'FS-WRITE-1'], aeeNewThing: true })], rows: () => IDS.map((id) => row(id, { containmentObserved: 'egress_captured', observationRefs: [0] })) }), { verdict: 'reject', code: 'RECORD_UNRECOGNIZED_RESERVED_MEMBER', primary: 'SEAL_REQUIRED_NONE_VALID' });
ok('the same statement with a seal that covers', build({ records: (c) => [interception(), sealed(c, { aeeObservedAttacks: ['CO-EXFIL-1', 'CO-EXFIL-2', 'FS-WRITE-1'] })], rows: () => IDS.map((id) => row(id, { containmentObserved: 'egress_captured', observationRefs: [0] })) }), 'fail');
noAmong('a seal of another run committing to another record set', allClean({ records: (c) => [arming(c), sealed(c, { aeeObservedAttacks: [] }), sealed(c, { aeeRunBinding: H('other run'), aeeObservedAttacks: [], aeeObservedSet: H('another set') })] }), 'SEAL_OBSERVED_SET_MISMATCH');

// ── attribution ──
no('pinned with no expectation in the corpus', build({ rows: () => [caughtRow({ attribution: 'paired' }), row('CO-EXFIL-2', { containmentObserved: 'egress_captured', attribution: 'pinned', actualLayer: 'none', observationRefs: [0] }), row('FS-WRITE-1')], records: (c) => [interception(), arming(c), sealed(c, { aeeObservedAttacks: ['CO-EXFIL-1', 'CO-EXFIL-2'] })] }), 'ROW_PINNED_NOT_SUPPORTED');
no('pinned over an interception carrying another commitment', build({ records: (c) => [interception({ aeePayloadCommitment: [H('another payload')] }), arming(c), sealed(c)] }), 'ROW_PINNED_NOT_SUPPORTED');
no('pinned on a clean row, which resolves no interception', allClean({ rows: () => IDS.map((id, i) => row(id, { observationRefs: [0, 1], ...(i === 0 ? { attribution: 'pinned' } : {}) })) }), 'ROW_PINNED_NOT_SUPPORTED');
no('pinned on an artifact row with no record', artifactOnly({ statement: (s) => { s.predicate.attackResults[0].attribution = 'pinned'; } }), 'ROW_PINNED_NOT_SUPPORTED');
ok('pinned where one of two commitments is the expected one', build({ records: (c) => [interception({ aeePayloadCommitment: [H('another payload'), H('payload-1')].sort() }), arming(c), sealed(c)] }), 'fail');

// ── the evidence tier ──
ok('a tampered signature: unattested for the row it covers, nothing else moves', build({ statement: (s) => { s.predicate.observationRecords[0].signatures[0].sig = Buffer.alloc(64, 7).toString('base64'); } }), 'fail', { tiers: ['unattested', 'attested', 'attested'] }, KEYS1);
ok('a keyid that names no pinned key is only a hint', build({ statement: (s) => { for (const r of s.predicate.observationRecords) r.signatures[0].keyid = 'someone-else'; } }), 'fail', { tiers: ['attested', 'attested', 'attested'] }, KEYS1);
ok('mixed bases: declared beside attested', build({ rows: () => [caughtRow(), row('CO-EXFIL-2'), { attackId: 'FS-WRITE-1', containmentObserved: 'no_egress', basis: 'artifact', method: 'intercepted', attribution: 'paired', actualLayer: 'none' }] }), 'fail', { tiers: ['attested', 'attested', 'declared'] }, KEYS1);
ok('a signature entry that is not a signature verifies nothing, and the statement stays valid', build({ statement: (s) => { s.predicate.observationRecords[0].signatures = [{}]; } }), 'fail', { tiers: ['unattested', 'attested', 'attested'] }, KEYS1);
ok('a keyid that is not a string is no hint at all', build({ statement: (s) => { for (const r of s.predicate.observationRecords) r.signatures[0].keyid = 7; } }), 'fail', { tiers: ['attested', 'attested', 'attested'] }, KEYS1);
ok('a second signature entry that verifies is enough', build({ statement: (s) => { const r = s.predicate.observationRecords[0]; r.signatures.unshift({ keyid: 'k0', sig: Buffer.alloc(64, 7).toString('base64') }); } }), 'fail', { tiers: ['attested', 'attested', 'attested'] }, KEYS1);
ok('a referenced moat-drop signed by a key that is not pinned: the row is unattested', build({ records: (c) => [interception(), arming(c), sealed(c), { p: { aeeKind: 'moat-drop', aeeMethod: 'intercepted' }, key: K2 }], rows: () => [caughtRow({ observationRefs: [0, 3] }), row('CO-EXFIL-2'), row('FS-WRITE-1')] }), 'fail', { tiers: ['unattested', 'attested', 'attested'] }, KEYS1);

{
  const signedWith = (key, alg) => build({ records: (c) => [interception(), arming(c), sealed(c)].map((s) => ({ ...s, key, alg })) });
  ok('records signed with Ed448', signedWith(K448), 'fail', { tiers: ['attested', 'attested', 'attested'] }, [{ key: K448.publicKey }]);
  ok('records signed with ECDSA P-256 over SHA-256', signedWith(KEC, 'sha256'), 'fail', { tiers: ['attested', 'attested', 'attested'] }, [{ key: KEC.publicKey }]);
  ok('records signed with ECDSA, an Ed25519 key pinned: unattested', signedWith(KEC, 'sha256'), 'fail', { tiers: ['unattested', 'unattested', 'unattested'] }, KEYS1);
}

// ── diagnostics stay bounded ──
{
  const long = 'Z'.repeat(300);
  const r = verifyStatement(artifactOnly({ coverage: { assessedClasses: ['CO', 'FS', long], outOfScope: {}, routedElsewhere: {} } }));
  const said = r.details.map((d) => d.message).join(' ');
  if (r.verdict === 'reject' && said.includes('(cut)') && !said.includes('Z'.repeat(65))) pass++;
  else { failed++; console.log('✗ a long statement string is cut in a diagnostic'); }
}
{
  const many = artifactOnly({ statement: (s) => { s.predicate.attackResults = Array.from({ length: 500 }, () => 7); } });
  const r = verifyStatement(many);
  if (r.verdict === 'reject' && r.codes.includes('ROW_MALFORMED') && r.details.length <= 64 && r.detailsDropped > 0) pass++;
  else { failed++; console.log(`✗ diagnostics bounded — ${r.details.length} details, ${r.detailsDropped} dropped`); }
}

// ── the command line contract ──
const dir = mkdtempSync(join(tmpdir(), 'aee-verify-'));
// stdout must be ONE line, one object, with exactly the members of the contract; a refusal adds primaryCode
const cli = (name, buf, env, wantCode, wantVerdict, wantTiers, flags = []) => {
  const f = join(dir, 'statement.json'); writeFileSync(f, buf);
  const r = spawnSync(process.execPath, [join(HERE, 'aee-verify.mjs'), ...flags, f], { encoding: 'utf8', env: { ...process.env, ...env } });
  // printable ASCII and one final newline: no line separator of any kind can hide in the line
  const oneLine = /^[ -~]+\r?\n$/.test(r.stdout);
  let last = null; try { last = JSON.parse(r.stdout); } catch { /* reported below */ }
  const wantKeys = wantVerdict === 'reject' ? 'codes,primaryCode,result,tiers,verdict' : 'codes,result,tiers,verdict';
  const good = r.status === wantCode && oneLine && last && Object.keys(last).sort().join(',') === wantKeys && last.verdict === wantVerdict
    && Array.isArray(last.codes) && (!wantTiers || JSON.stringify(last.tiers) === JSON.stringify(wantTiers))
    && (flags.includes('--explain') && wantVerdict === 'reject' ? /^[ -~\r\n]+$/.test(r.stderr) : r.stderr === '' || env.AEE_SUBSTRATE_KEYS !== undefined);
  if (good) pass++; else { failed++; console.log(`✗ ${name} — exit ${r.status}, stdout ${JSON.stringify(r.stdout.slice(0, 300))} stderr ${JSON.stringify(r.stderr.slice(0, 300))}`); }
};
const hexKey = K1.publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('hex');
const policy = join(dir, 'keys.json');
writeFileSync(policy, JSON.stringify({ substrateObservationKeys: [{ keyid: 'k1', publicKeyHex: hexKey }] }));
const policyBom = join(dir, 'keys-bom.json');
writeFileSync(policyBom, BOM + JSON.stringify({ substrateObservationKeys: [{ keyid: 'k1', publicKeyHex: hexKey }] }));
const policySpki = join(dir, 'keys-spki.json');
writeFileSync(policySpki, JSON.stringify({ substrateObservationKeys: [{ publicKeyHex: K1.publicKey.export({ format: 'der', type: 'spki' }).toString('hex') }] }));
delete process.env.AEE_SUBSTRATE_KEYS;
cli('cli: accept, exit 0, key pinned', build(), { AEE_SUBSTRATE_KEYS: policy }, 0, 'accept', ['attested', 'attested', 'attested']);
cli('cli: a key policy saved with a byte order mark', build(), { AEE_SUBSTRATE_KEYS: policyBom }, 0, 'accept', ['attested', 'attested', 'attested']);
cli('cli: a key given as a DER SubjectPublicKeyInfo, without keyid', build(), { AEE_SUBSTRATE_KEYS: policySpki }, 0, 'accept', ['attested', 'attested', 'attested']);
cli('cli: accept, exit 0, no key', build(), {}, 0, 'accept', ['unattested', 'unattested', 'unattested']);
cli('cli: an unreadable key policy pins nothing', build(), { AEE_SUBSTRATE_KEYS: join(dir, 'absent.json') }, 0, 'accept', ['unattested', 'unattested', 'unattested']);
cli('cli: reject, exit 1', build({ result: 'pass' }), {}, 1, 'reject', []);
cli('cli: reject with --explain: the findings go to stderr, stdout stays one line', build({ result: 'pass' }), {}, 1, 'reject', [], ['--explain']);
cli('cli: a refusal quoting statement strings with line separators keeps stdout one ASCII line', artifactOnly({ result: 'pass' + LS + NEL + 'x', coverage: { assessedClasses: ['CO', 'FS', 'Z' + PS + 'Z'], outOfScope: {}, routedElsewhere: {} } }), {}, 1, 'reject', [], ['--explain']);
{
  const r = spawnSync(process.execPath, [join(HERE, 'aee-verify.mjs')], { encoding: 'utf8' });
  if (r.status === 2 && r.stdout === '') pass++; else { failed++; console.log(`✗ cli: no argument — exit ${r.status}`); }
  const r2 = spawnSync(process.execPath, [join(HERE, 'aee-verify.mjs'), join(dir, 'absent.json')], { encoding: 'utf8' });
  if (r2.status === 2 && r2.stdout === '') pass++; else { failed++; console.log(`✗ cli: unreadable file — exit ${r2.status}`); }
}

console.log(`${failed === 0 ? '✅' : '⛔'} ${pass}/${pass + failed} cases hold — ${accepts} accepted statements, ${refusals.size} distinct refusal codes exercised`);
process.exitCode = failed === 0 ? 0 : 1;
