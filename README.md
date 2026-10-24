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

Not read before this build was posted: the conformance vectors, their changelog, the two outside verifiers, the reference rail, and the README's registry of condition codes. The registry was left unread on purpose: it is a checklist derived from another implementation. The `codes` this verifier emits are therefore its own names for the rules it enforces: where one of them matches a name in the registry, that is a coincidence of wording and not a shared definition.

Not read either, before or since: the parsing rules of the in-toto Attestation Framework, which the specification opts into (line 388 of the pinned file). Readings 3 and 7 (how a typed member is read) and reading 6 (what a member the predicate no longer defines does to a statement) rest on this build's own reading, not on those rules.

Seen earlier, and declared on the invitation thread: in August 2026 the repository (then `astrogilda/aee-conformance`) was explored through the GitHub API: its README, its file tree (250 vectors counted), its forcing-campaign figures, and the eight vectors described in one of its issues.

Tools: written by a coding agent, Claude Code running Claude Opus 5.5. Before the first commit the code was reviewed by fifteen sub-agents of the same model, each given the specification, the code, this file and the bench, and nothing else; the defects they found were corrected, and the open readings they found are listed below. The August reading used Claude Code with Claude Opus 5.

## Readings taken where the text left one open

Each of these is a place where two careful readers could differ. They are listed so that a disagreement with another build can be traced to a reading rather than to a bug. Line numbers refer to the specification file at the pinned revision. Readings 6 and 12 were changed by the repair described below; reading 10 now points to reading 12; reading 25 is marked.

### The JSON layer

1. **Integers at or above 2^53** are judged on the value, not on the spelling. A number whose double value has a magnitude at or above 2^53 is rejected, statement-wide and inside record payloads, however its token is written (`9007199254740992`, `9007199254740992.0`, `1e16`). A number beyond the double range is rejected on the same ground.
2. **Byte order mark.** A leading U+FEFF is a syntax error.
3. **A JSON `null` is a value, not an absence.** `doesNotAssert`, `observationRecords` or `batchRoot` carried as `null` is mistyped, and the statement is refused.

### The statement

4. **`_type`** must be the in-toto Statement v1 type, and **`subject[0]`** must carry a `sha256` digest string on a statement of any basis.
5. **Digest spelling without a substrate row.** The lowercase 64-hex requirement on the `substrate`, `catchPolicy`, `networkPosture` and `subject[0]` digests is enforced only on a statement carrying a `basis: substrate` row, as the sentence that states it is scoped; without such a row they must still be present and carry a string. `runEntropy` is read only on a statement carrying a `basis: substrate` row. `corpus.name`, `corpus.uri` and `substrate.name` are never read.
6. **Earlier spellings** are refused: a predicate carrying `does_not_assert` or `interceptRecords`, or a row carrying `interceptRefs`, makes the statement invalid. The text says the old `does_not_assert` spelling is rejected and is not accepted as an alias (lines 1100-1101, 1779, 1974-1976), and that `interceptRecords` and `interceptRefs` were renamed with the old spellings rejected and no alias (lines 2033-2034). It states no other consequence, so "rejected" is read as the refusal of a statement that carries one; this remains a reading of that word. Changed by the repair: the first commit ignored them as unknown members, by analogy with the 0.4 row values, which the text also calls rejected (line 1986) but for which it states a consequence, a fail-closed row (lines 1093-1099). Before the first commit, one of the reviewing sub-agents had proposed this refusal; it was withdrawn then, by that analogy.
7. **`doesNotAssert`** is never required; when present and not an array of strings the statement is malformed.
8. **Coverage.** `assessedClasses`, `outOfScope` and `routedElsewhere` must all be present, the last two as maps from a class code to a string. A class code the manifest does not declare, anywhere in the three, makes the statement malformed. Coverage integrity compares the `attackId`s of all rows with the attacks of the assessed classes, so a row for an attack of a class disclosed out of scope is refused.
9. **Duplicates the text does not forbid** are accepted: a class listed twice in `assessedClasses` (it counts once), an attack listed twice inside one class, an index listed twice in one `observationRefs`.
10. **Row members.** A `containmentObserved`, `basis`, `method` or `attribution` that is absent or not a string is treated as out of vocabulary (fail-closed), not as a malformed statement (lines 1093-1097, 1110-1111). Two requirements the text states elsewhere still apply: a `basis: substrate` row whose `containmentObserved` or `method` is out of vocabulary cannot be covered, so the statement is invalid (lines 760-763; so already at the first commit); and a row whose attack has no `expectedPayloads` entry must declare `paired` (reading 12). `actualLayer` must be a string, and on a clean row it must be the literal `none`.
11. **`observationRefs` entries** must be written as integer tokens: `0.0` is not an index, and `-0` is index 0.
12. **Attribution with no expectation.** A row whose attack has no `expectedPayloads` entry must declare `attribution: paired`, or the statement is invalid; `pinned` on such a row is refused, as before. The sentence that says so is one of the coverage validity requirements, a violation of which makes the attestation invalid (lines 569-572, 618-619), and these requirements are consumption preconditions (lines 625-629). The general rule that a missing or out-of-vocabulary `attribution` is fail-closed governs `result` on a valid statement; it does not lift a precondition. Changed by the repair: the first commit read the sentence as the other face of the `pinned` rule and let such a row fail closed, which was a misreading.

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
25. **`aeeAssessedAttacks` and `aeeObservedAttacks`** are enforced as statement rules on the `arming` and `sealed` records that bind to this run. On a statement with no `basis: substrate` row no binding is derived, so they are not evaluated there. In part, this reading has the fault that reading 12 had before the repair; it was found after the repair and is left as it is. The text states both rules with no condition on the presence of a `basis: substrate` row (lines 1471-1473, 1539-1542), and it counts on the arming rule applying to a record kept on a statement with no such row left (lines 1481-1483); "binds to this run" is the condition it places on another requirement (line 595). So a statement with no `basis: substrate` row that carries an arming record declaring fewer attacks than are assessed is accepted here and invalid on the text. Whether a record of another run is held to the two rules, the text does not settle: it defines both arrays as this run's (lines 1467-1469, 1535-1537).
26. **The seal's posture digest** is compared, on a check that reads no row, against the pinned digest only; on a clean row it must also equal that of every arming record the row resolves.

### The evidence tier

27. **A row that is neither `artifact` nor `substrate`** (an out-of-vocabulary `basis`) derives the tier `declared`.
28. **Tier.** A row is `attested` when every record it references verifies, a referenced record of a kind that covers nothing included; a record verifies when any one of its signatures verifies under any pinned key, and `keyid` is not read, in the envelope or in the policy. Signatures are checked only on records a `basis: substrate` row references: a carried record no such row references (the seal of a statement whose rows are all caught, for one) is never verified, and nothing reports its status.
29. **Keys.** A 32-byte `publicKeyHex` is read as a raw Ed25519 public key; any other length as a DER SubjectPublicKeyInfo. An Ed25519 or Ed448 key verifies as such; any other key type verifies with the runtime's defaults for that type over SHA-256 (for ECDSA, a DER-encoded signature).

### Time, and order of evaluation

30. **Timestamps.** `:60` is admitted only at `23:59:60`, on any date. Any four-digit year and any number of fraction digits are admitted, and fractions are compared exactly.
31. **A statement that is malformed** (step 1) is not evaluated further: later steps would report conditions that follow from the first.

## The repair

The first commit, `2849417`, is the build as posted for the study, and it stays as it was. A second commit changes what the verifier does on readings 6 and 12, and nothing else in the code. The study's author reported that this build disagreed with the public corpus on three statements, and both readings were then re-read against the text: one statement carries `does_not_assert` (reading 6), one has a row with no `attribution` and one a row with `attribution: example_strong` (reading 12).

What the repair knows that the first build did not: those three statements, as the author's messages on the invitation thread describe them, and the result the study expects for each. The new bench cases are built from the text, like the others, except the value `example_strong`, which comes from those messages. Six of them carry the features the messages describe (two with `does_not_assert`, three with a missing `attribution`, one with `attribution: example_strong`), and two control cases carry the last two on an attack that has an entry.

Also seen since the first commit. In comments on in-toto/attestation#570: the vector count the test set's changelog gives and one vector identifier (declared on the invitation thread on 17 October), and, in the same comments, another build's results (that, like this one, it rejected the 213 sealed records the study's generator had broken, and its score on the public corpus). On 17 October, GenAI-Security-Project/agent-control-standard#29 was read in full; a comment of 14 October there describes two members of the `vectors-observed-effect` set (agent-evidence-vectors 0.18.1) and links their files, which were not opened. Since the first commit, nothing in the test-set repository was opened.

The code change is three additions, with no line removed. A statement whose predicate carries `does_not_assert` or `interceptRecords`, or with a row that carries `interceptRefs`, is refused (`OLD_SPELLING_CARRIED`). A row whose attack has no `expectedPayloads` entry and that does not declare `attribution: paired` is refused (`ROW_NO_EXPECTATION_NOT_PAIRED`). In the bench, the two cases that encoded the old readings were removed, and twelve cases were added: a refusal for each earlier spelling and for each shape of reading 12, and control cases that differ from them by one fact (a missing or out-of-vocabulary `attribution` on a row whose attack has an entry still fails closed; `paired` on every row passes).

Measured on the repair:

- the bench passes 256/256 on both platforms named above;
- run against the first commit's verifier, the new bench fails on exactly the nine new refusals (247/256), so each of them depends on the change;
- each of eight altered versions of the new checks makes the bench fail: the check of the two predicate spellings removed, or of either one, or of `interceptRefs`; the `paired` rule removed, or inverted; the rule without its condition that the attack has no `expectedPayloads` entry; the rule extended to `pinned`;
- the 246 statements the bench passes to the verifier in-process were each judged by both versions: they differ on nine, all of them cases of readings 6 and 12, and the other 237 are identical in verdict, codes, result and tiers.

A pass over the other 29 readings, looking for the same two faults (a general rule applied where the text states a validity requirement; an analogy where the text has its own word), found one more, in part: reading 25, marked there and left as it is.

The repair was written by the same coding agent and model as the first commit. Before the second commit it was reviewed by three sub-agents of the same model, each given the pinned specification, both versions of the code and of the bench, the measurement outputs, the commit message and the report, and our working notes, which record the exposures declared above. They found no fault in the code; their objections narrowed reading 25 and corrected the wording of this file and of the report.

## Limits

This verifier checks one statement. It does not verify the enclosing envelope, pin a corpus or a substrate, or apply any consumer policy beyond the evidence tier.

Its bench (246 cases at the first commit, 256 after the repair) is written by the same reader as the verifier, so the two can agree with each other and both be wrong about the text. A case count is also no measure of what the bench holds, so that was measured apart, on the code of the first commit and on the code after the repair: in both, of the 37 comparisons in `aee-verify.mjs` that a mutation tool could cut one at a time, 36 make the bench fail when cut. The tool cuts only what it knows how to cut, so the figure says nothing about the rest of the file. The one that does not fail is the requirement that a seal's posture digest equal that of every arming record a clean row resolves: it is implemented as the text states it, and it cannot be the only ground of a refusal, because an arming record of this run whose posture digest is not the pinned one already invalidates the statement, and one of another run already fails the run-binding requirement.

## Licence

Apache-2.0. Copyright 2026 Avp9 (Jérémy Martin).
