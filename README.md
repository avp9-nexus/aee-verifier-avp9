# aee-verify — a verifier for Adversarial Execution Evidence v0.7, built from the specification text

One file, no dependency beyond the Node.js standard library. It reads one in-toto statement and says whether it is valid under the predicate `https://in-toto.io/attestation/adversarial-execution-evidence/v0.7`, and why not.

It was run on Node.js 24.15 (Windows 11) and Node.js 22.22 (Linux, WSL2); no older version was tried.

It was built for the study described in `probityai/agent-evidence-vectors`, `docs/study/emse-2026/builders.md`.

## Run it

```
node aee-verify.mjs <statement.json>
```

Exit status 0 means the statement is valid, 1 means it is invalid, 2 means nothing was judged: a usage or I/O error, or an internal error of the verifier, which is never reported as a verdict.

stdout is one line, one JSON object:

```
{"verdict":"accept","codes":[],"result":"pass","tiers":["attested"]}
{"verdict":"reject","codes":["RESULT_MISMATCH"],"result":null,"tiers":[],"primaryCode":"RESULT_MISMATCH"}
```

`tiers` holds one evidence tier per `attackResults` row, in row order. On a rejected statement `result` is `null` and `tiers` is empty, because neither may be consumed. `primaryCode` is present on a refusal only. The line is printable ASCII and holds no string taken from the statement.

`node aee-verify.mjs --explain <statement.json>` adds, on stderr, one line per finding (which row, which record), at most 64.

The consumer key policy is read from the path in the environment variable `AEE_SUBSTRATE_KEYS`, holding `{"substrateObservationKeys":[{"keyid":"...","publicKeyHex":"..."}]}`. Without it, every `basis: substrate` row derives `unattested`. A policy file that cannot be read or parsed pins nothing, and a warning says so on stderr.

`node test.mjs` runs the verifier's own bench.

## What it was built from, and what was not read

Read: the specification at the pinned revision (`v0.12.1`, `spec/predicates/adversarial-execution-evidence.md`, SHA-256 `759d2383e5da36fa509dc335e6159a20b87641b25ebbadcf1676c55d75ffd8b0`), in full; the three study pages (`builders.md`, `readers.md`, `coders.md`); and, from the 0.12.1 README on PyPI, the section "What the suite compares" plus the one sentence of "Run the suite against your verifier" that states the command-line contract.

Not read before this build was posted: the conformance vectors, their changelog, the two outside verifiers, the reference rail, and the README's registry of condition codes. The registry was left unread on purpose: it is a checklist derived from another implementation. The `codes` this verifier emits are therefore its own names for the rules it enforces, and they will not intersect the registry's.

Seen earlier, and declared on the invitation thread: in August 2026 the repository (then `astrogilda/aee-conformance`) was explored through the GitHub API: its README, its file tree (250 vectors counted), its forcing-campaign figures, and the eight vectors described in one of its issues.

Tools: written by a coding agent, Claude Code running Claude Opus 5.5. Before the first commit the code was reviewed by fifteen sub-agents of the same model, each given the specification, the code, this file and the bench, and nothing else; the defects they found were corrected, and the open readings they found are listed below. The August reading used Claude Code with Claude Opus 5.

## Readings taken where the text left one open

Each of these is a place where two careful readers could differ. They are listed so that a disagreement with another build can be traced to a reading rather than to a bug.

### The JSON layer

1. **Integers at or above 2^53** are judged on the value, not on the spelling. A number whose double value has a magnitude at or above 2^53 is rejected, statement-wide and inside record payloads, however its token is written (`9007199254740992`, `9007199254740992.0`, `1e16`). A number beyond the double range is rejected on the same ground.
2. **Byte order mark.** A leading U+FEFF is a syntax error.
3. **A JSON `null` is a value, not an absence.** `doesNotAssert`, `observationRecords` or `batchRoot` carried as `null` is mistyped, and the statement is refused.

### The statement

4. **`_type`** must be the in-toto Statement v1 type, and **`subject[0]`** must carry a `sha256` digest string on a statement of any basis.
5. **Digest spelling without a substrate row.** The lowercase 64-hex requirement on the `substrate`, `catchPolicy`, `networkPosture` and `subject[0]` digests is enforced only on a statement carrying a `basis: substrate` row, as the sentence that states it is scoped; without such a row they must still be present and carry a string. `runEntropy` is read only on a statement carrying a `basis: substrate` row. `corpus.name`, `corpus.uri` and `substrate.name` are never read.
6. **Earlier spellings** (`does_not_assert`, `interceptRecords`, `interceptRefs`) are unknown members: they are not read as aliases, and they are ignored, not a ground for refusal. The change history says the old spellings are rejected; it uses the same words for the 0.4 row values, whose stated consequence is a fail-closed row and not an invalid statement, and the field text says only that the old spelling is not accepted as an alias.
7. **`doesNotAssert`** is never required; when present and not an array of strings the statement is malformed.
8. **Coverage.** `assessedClasses`, `outOfScope` and `routedElsewhere` must all be present, the last two as maps from a class code to a string. A class code the manifest does not declare, anywhere in the three, makes the statement malformed. Coverage integrity compares the `attackId`s of all rows with the attacks of the assessed classes, so a row for an attack of a class disclosed out of scope is refused.
9. **Duplicates the text does not forbid** are accepted: a class listed twice in `assessedClasses` (it counts once), an attack listed twice inside one class, an index listed twice in one `observationRefs`.
10. **Row members.** A `containmentObserved`, `basis`, `method` or `attribution` that is absent or not a string is treated as out of vocabulary (fail-closed), not as a malformed statement. `actualLayer` must be a string, and on a clean row it must be the literal `none`.
11. **`observationRefs` entries** must be written as integer tokens: `0.0` is not an index, and `-0` is index 0.
12. **Attribution with no expectation.** A row whose attack has no `expectedPayloads` entry and whose `attribution` is missing or out of vocabulary is fail-closed: it forces `fail` and the statement stays valid. Only `attribution: pinned` without its support is refused. The sentence saying that such a row must declare `paired` is read as the other face of the `pinned` rule inside a two-value vocabulary, not as a second ground for refusal.

### Records

13. **`batchRoot`** is compared as a lowercase hex string, so the right root spelled in uppercase is refused. With no record, a carried `batchRoot` is refused: there is nothing it could recompute over. `observationRecords: []` is read as no record.
14. **Envelope.** `payload` must be standard, padded, canonical base64; anything else makes the record, and so the statement, malformed. `signatures` must be an array with at least one entry, and stage one reads none of them: an entry that is not an object with a string `sig` verifies nothing, and `sig` is decoded leniently, since a signature either verifies or does not.
15. **Duplicate records** are compared by leaf hash, so two envelopes with the same `payloadType` and payload bytes are duplicates even when their signatures differ.
16. **A media type "ending in `+json`"** is tested on the literal end of the string; a parameter after it defeats the test.
17. **A record whose payload cannot be read has no kind.** When the payload is not a canonical RFC 8785, strict I-JSON object with BMP-only member names under a `+json` media type, none of its fields is read (a payload holding an integer at or above 2^53 is one such case). The record still enters `batchRoot`, and a `basis: substrate` row that references it is invalid. Otherwise it is inert: it is not an interception a caught row must account for, it stays outside the `aeeObservedSet` recompute, and no constraint applies to it.
18. **The third per-row requirement applies to every record a `basis: substrate` row references**, whatever its kind, the kinds that cover nothing included: the payload must be readable (17), carry `aeeRunBinding`, `aeeKind` and `aeeMethod` as strings, and bind to this run. The value of `aeeMethod` is constrained only on the four covering kinds.
19. **A record of a covering kind ends in one of three states.** It covers. Or it violates a constraint its kind states (the kind's own list, the seal's conditions, the member 0.7 requires of it): it covers nothing, and when it binds to this run the statement is invalid, referenced or not. Or it is only weakened: it covers nothing, so it can be neither the record a row rests on nor the seal a statement must carry, but it is not itself a ground for refusal. The weakening faults are: an unrecognized `aee*` top-level member (`aeeVersion` included; names nested deeper are not looked at); a run-sequence syntax fault on an `arming` record; a declared `aeeBindingVersion` other than the JSON string `"2"`, on any covering kind; on an `interception`, an `aeeMethod` that is missing or outside the vocabulary (the other three kinds fix its value by a rule of their own, and breaking that rule is a violation). A defined `aee*` member carried on a kind that does not define it has no other consequence.
20. **Binding version.** A referenced record that declares another binding version and carries another digest is reported as an unsupported version, not as a digest mismatch.
21. **Run-sequence syntax.** `aeeRunSeq` must be a positive integer token and comes with `aeeChainScope`; `aeePrevRunBinding` must be absent when `aeeRunSeq` is 1 and a lowercase 64-hex value otherwise.
22. **Seal numbers.** `aeeDropCount` must be a non-negative integer token, and `aeeDropBound`, when present, an integer token, even where the count is zero.
23. **The method cap** is read over the records a row resolves that cover; a record that covers nothing is outside it.
24. **`aeeObservedSet`** is recomputed over every carried record whose payload reads as `interception` or `examination`, whatever run it binds to, and is required to match on every carried `sealed` record, whatever run it binds to.
25. **`aeeAssessedAttacks` and `aeeObservedAttacks`** are enforced as statement rules on the `arming` and `sealed` records that bind to this run. On a statement with no `basis: substrate` row no binding is derived, so they are not evaluated there.
26. **The seal's posture digest** is compared, on a check that reads no row, against the pinned digest only; on a clean row it must also equal that of every arming record the row resolves.

### The evidence tier

27. **A row that is neither `artifact` nor `substrate`** (an out-of-vocabulary `basis`) derives the tier `declared`.
28. **Tier.** A row is `attested` when every record it references verifies, a referenced record of a kind that covers nothing included; a record verifies when any one of its signatures verifies under any pinned key, and `keyid` is not read, in the envelope or in the policy. Signatures are checked only on records a `basis: substrate` row references: a carried record no such row references (the seal of a statement whose rows are all caught, for one) is never verified, and nothing reports its status.
29. **Keys.** A 32-byte `publicKeyHex` is read as a raw Ed25519 public key; any other length as a DER SubjectPublicKeyInfo. An Ed25519 or Ed448 key verifies as such; any other key type verifies with the runtime's defaults for that type over SHA-256 (for ECDSA, a DER-encoded signature).

### Time, and order of evaluation

30. **Timestamps.** `:60` is admitted only at `23:59:60`, on any date. Any four-digit year and any number of fraction digits are admitted, and fractions are compared exactly.
31. **A statement that is malformed** (step 1) is not evaluated further: later steps would report conditions that follow from the first.

## Limits

This verifier checks one statement. It does not verify the enclosing envelope, pin a corpus or a substrate, or apply any consumer policy beyond the evidence tier.

Its bench (246 cases at the first commit) is written by the same reader as the verifier, so the two can agree with each other and both be wrong about the text. A case count is also no measure of what the bench holds, so that was measured apart: of the 37 comparisons in `aee-verify.mjs` that a mutation tool could cut one at a time, 36 make the bench fail when cut. The tool cuts only what it knows how to cut, so the figure says nothing about the rest of the file. The one that does not fail is the requirement that a seal's posture digest equal that of every arming record a clean row resolves: it is implemented as the text states it, and it cannot be the only ground of a refusal, because an arming record of this run whose posture digest is not the pinned one already invalidates the statement, and one of another run already fails the run-binding requirement.

## Licence

Apache-2.0. Copyright 2026 Avp9 (Jérémy Martin).
