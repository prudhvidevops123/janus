# Canonical JSON

Canonical JSON encoding is used to ensure deterministic hashing across languages and OSes.

## Rules

- Objects: keys are sorted lexicographically and encoded without extra whitespace.
- Arrays: preserve order and encode elements canonically.
- Strings: UTF-8 JSON strings with standard escaping.
- Integers: encoded as numbers with no leading zeros.
- Floats: MUST be encoded as strings to avoid precision ambiguity.
- `null`, `true`, `false` are encoded as standard JSON literals.

## Hashing

- `params_hash = sha256(canonical_json(params_normalized))`
- `policy_bundle_hash = sha256(canonical_json(typed_bundle))`
- Hex-encoded lowercase digest.

## YAML Input Rule

- YAML is a convenience authoring format only.
- When a policy bundle is provided as YAML, Nomos decodes YAML into typed structs first.
- Nomos then converts that typed bundle into canonical JSON.
- The canonical JSON form is the only input used for `policy_bundle_hash`.
- Equivalent JSON and YAML bundles therefore hash identically when they represent the same typed bundle.

## Test Vector

Input:

```json
{"b":1,"a":"x","c":[true,2]}
```

Canonical JSON:

```json
{"a":"x","b":1,"c":[true,2]}
```

Expected SHA-256:

```
04ceb95b6eab660e1db5b4cf9e1d8ad320a4772a2a22775bb679d53daabd84f2
```
