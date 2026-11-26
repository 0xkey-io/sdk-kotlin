# OpenAPI sources

The specs in this directory are copied from the 0xkey JS SDK
(`github.com/0xkey-io/sdk-js`) at commit `adbcfeaa05e43970fb2c9f8a4747d90177196a35`.
They replace the upstream specs; regenerate with
`./gradlew :packages:types:types-codegen :packages:http:client-codegen`.

| File | Source path in sdk-js | sha256 |
| --- | --- | --- |
| `public_api.swagger.json` | `contracts/services-public-api.swagger.json` | `7e42c12692674e8bbc594ecf458a383b18c17f48ddfeb76f549bf220247a4f49` |
| `auth_proxy.swagger.json` | `packages/core/src/__inputs__/auth_proxy.swagger.json` | `6b035dbbae61dfbe4533a1e24ccbe2e83ef56ccf81023a38b2ae47535c9c71fe` |
| `sdk_compatibility_definitions.json` | `contracts/sdk-compatibility-definitions.json` | `d71f9343a6bac827c2e80038af7560550cb81c7539b10d3b6a475180dc7fbc4f` |

`public_api.swagger.json` is an unmodified copy of the source (the source no longer needs local
description edits).

`sdk_compatibility_definitions.json` holds SDK-side definitions (client-signature token usage,
transaction failure details, WebAuthn stamp). The types generator merges them into the public spec
and lets them override same-named definitions, matching the JS SDK's OpenAPI projection.

## Generation scope

- Public API: only POST operations under `/public/v1/query/` and `/public/v1/submit/` are generated
  (140 of 144 paths). Auth Proxy: all 13 operations.
- Compared with the upstream spec (177 public paths), 53 upstream public paths no longer exist
  in the 0xkey spec (swap, earn, TVC, velocity control, IP allowlist, ...) and 21 paths are new.
  The generated client went from 367 to 293 public methods.

## Nullability

`codegen-policy.json` defines which swagger-required message (object `$ref`) properties stay
non-optional. Every other message property on models and responses is generated as nullable with a
`null` default, because production omits or nulls fields such as `createdAt`, `votes[].user` and
sibling `result` branches. The generator verifies the non-optional count against
`expectedNonOptionalMessageProperties` and emits `GeneratedNullabilityTest`, which decodes every
generated type with those properties both `null` and absent.
