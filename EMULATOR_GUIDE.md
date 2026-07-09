# OAC Policy Emulator Guide

## Overview

The OAC Policy Emulator is a standalone CLI tool that executes the real Orthogonal Access Control (OAC) Policy Decision Point (PDP) 9-rule decision chain **without any infrastructure dependencies**. No Spring Boot, no MongoDB, no Docker — pure Java.

It wires the same production `DecisionApplicationService` class with in-memory adapters:

| Production Component | Emulator Replacement |
|---|---|
| `MongoPolicyRegistryAdapter` | `InMemoryPolicyRegistryAdapter` |
| `MongoRelationshipGraphAdapter` | `InMemoryRelationshipGraphAdapter` |
| `MongoAttributeResolverAdapter` | `InMemoryAttributeResolverAdapter` |
| `MongoAuditEvidenceAdapter` | `InMemoryAuditEvidenceAdapter` |
| `MongoConsistencyTokenAdapter` | In-memory `ConsistencyTokenStore` anonymous class |

## Quick Start

### Prerequisites

- Java 17+
- Maven 3.8+

### Build

```bash
# From the repository root
mvn package -pl libraries/standalone-emulator,emulator -am -DskipTests -q
```

### Run a Test Suite

```bash
java -jar emulator/target/oac-policy-emulator-cli-0.1.0-SNAPSHOT.jar \
  --test \
  emulator/src/test/resources/test-data/precedence/policies.json \
  emulator/src/test/resources/test-data/precedence/relationships.json \
  emulator/src/test/resources/test-data/precedence/testcases.json
```

### Run a Single Evaluation

```bash
# From a JSON string
java -jar emulator/target/oac-policy-emulator-cli-0.1.0-SNAPSHOT.jar \
  --single \
  policies.json relationships.json \
  '{"subject":{"id":"user-reader","type":"human"},"action":"read","resource":{"type":"account","id":"acc-1"},"boundaryContext":{"tenant":"tenant-a","geography":"us","market":"retail","lineOfBusiness":"cards","channel":"staff"}}'

# From a file
java -jar emulator/target/oac-policy-emulator-cli-0.1.0-SNAPSHOT.jar \
  --single \
  policies.json relationships.json \
  check-request.json

# From stdin
echo '{"subject":{"id":"user-reader","type":"human"},"action":"read","resource":{"type":"account","id":"acc-1"}}' | \
java -jar emulator/target/oac-policy-emulator-cli-0.1.0-SNAPSHOT.jar \
  --single \
  policies.json relationships.json
```

## Modes of Operation

### `--test` Mode (Batch Test Suite)

Executes a list of test cases and reports pass/fail for each. Exit code is `0` if all pass, `1` if any fail.

```
Usage: --test <policies.json> <relationships.json> <testcases.json>
```

Output format:

```
OAC Policy Emulator
  Loaded 6 policies
  Loaded 3 relationships

Running 5 test cases...

  ✅ Alice reads order → ALLOW (DECISION_POLICY_ALLOW)
  ✅ Attacker denied → DENY (DECISION_EXPLICIT_DENY)
  ❌ Unknown user → DENY (expected: ALLOW)
     Decision code: DECISION_DEFAULT_DENY
     Matched policies: []
     Explanation: evidence://decision/default-deny

=== Results: 2 passed, 1 failed ===
```

### `--single` Mode (One-shot Evaluation)

Evaluates a single `CheckPermission` request and prints the full decision output. Useful for ad-hoc testing and debugging.

```
Usage: --single <policies.json> <relationships.json> [request-json-or-file]
```

Output format:

```
=== Decision ===
  Decision:       ALLOW
  Code:           DECISION_POLICY_ALLOW
  Matched:        [POL.ALLOW.POL.RBAC.ACCOUNT.READ.ALLOW.v1]
  Explanation:    evidence://decision/policy-allow
  Field masks:    {customer.email=MASK, customer.ssn=NONE}
  Evaluated at:   2026-07-09T10:00:00.123456+08:00
```

## Input File Formats

### Policies JSON

An array of policy objects. Each policy supports these fields:

| Field | Type | Required | Description | Example |
|---|---|---|---|---|
| `name` | string | Yes | Unique policy identifier | `"POL.RBAC.ACCOUNT.READ.ALLOW.v1"` |
| `state` | string | Yes | Only `"ACTIVE"` policies are evaluated | `"ACTIVE"` |
| `effect` | string | Yes | `"ALLOW"` or `"DENY"` | `"ALLOW"` |
| `action` | string | No | Action verb or `"*"` for any | `"read"`, `"approve"`, `"*"` |
| `resourceType` | string | No | Resource type or `"*"` for any | `"account"`, `"order"` |
| `resourceId` | string | No | Specific resource instance | `"acc-1"` |
| `subjectId` | string | No | Specific subject | `"user-reader"` |
| `subjectType` | string | No | `"human"` or `"workload"` | `"workload"` |
| `tenant` | string | No | Tenant scope | `"tenant-a"`, `"acme"` |
| `geography` | string | No | Geography scope | `"us"`, `"EU"`, `"*"` |
| `market` | string | No | Market scope | `"retail"`, `"enterprise"` |
| `lineOfBusiness` | string | No | LOB scope | `"cards"`, `"supply-chain"` |
| `channel` | string | No | Channel scope | `"staff"`, `"customer"`, `"system"` |
| `spelCondition` | string | No | SpEL expression evaluated at priority 5 | `"subject.department == 'compliance'"` |
| `requiredRelationship` | string | No | ReBAC type, evaluated at priority 7 | `"manages"`, `"owner"` |
| `fieldMasks` | array | No | Field-level access masks | See [Field Masking](#field-masking) |
| `timeWindow` | string | No | Business hours caveat | `"09:00-17:00 UTC"` |
| `sourceIpRange` | string | No | Allowed CIDR | `"10.0.0.0/8"` |

#### Matching Rules

- **Subject match**: `subjectId` matches request subject id, or is absent (matches all)
- **Action match**: `action` matches request action, or is `"*"`, or is absent
- **Resource type match**: `resourceType` matches request resource type, or is `"*"`, or is absent
- **Boundary match**: For each of tenant, geography, market, LOB, channel — field matches request value, or is `"*"`, or is absent (matches all)

If a field is absent from the policy, it matches all values for that dimension.

### Relationships JSON

An array of relationship edge objects:

| Field | Type | Required | Description | Example |
|---|---|---|---|---|
| `subjectId` | string | Yes | Source node ID | `"alice"` |
| `subjectType` | string | No | Source node type | `"human"` |
| `relationshipType` | string | Yes | Edge type label | `"manages"`, `"owner"` |
| `resourceId` | string | Yes | Target node ID | `"ORD-001"` |
| `resourceType` | string | No | Target node type | `"order"` |
| `expiresAt` | string | No | ISO-8601 expiry timestamp. Expired edges are skipped in BFS traversal | `"2024-01-01T00:00:00Z"` |

### Test Cases JSON

An array of test case objects:

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | Yes | Display name for the test |
| `request` | object | Yes | A complete `CheckPermission` request (see below) |
| `expected` | string | Yes | Expected decision: `"ALLOW"` or `"DENY"` |

### CheckPermission Request Format

```json
{
  "subject": {
    "type": "human",
    "id": "user-reader",
    "department": "compliance"
  },
  "action": "read",
  "resource": {
    "type": "account",
    "id": "acc-1"
  },
  "boundaryContext": {
    "tenant": "tenant-a",
    "geography": "us",
    "market": "retail",
    "lineOfBusiness": "cards",
    "channel": "staff"
  },
  "runtimeContext": {
    "requestTime": "2026-06-24T14:00:00Z",
    "sourceIp": "10.0.0.55",
    "riskScore": "50",
    "requesterId": "bob",
    "piiClassification": [
      {"fieldPattern": "*.email", "accessLevel": "MASK"}
    ],
    "fieldMasks": [
      {"field": "customer.email", "level": "READ"}
    ]
  },
  "consistencyToken": "token-abc-123"
}
```

#### Subject Attributes

Subject properties beyond `type` and `id` are placed directly in the subject object (e.g. `"department": "compliance"`). Available subject variables for SpEL:

- `subject.id` — String
- `subject.type` — String
- `subject.department` — String
- `subject.market` — String
- `subject.lob` — String
- `subject.geography` — String
- `subject.channel` — String
- `subject.tenant` — String
- `subject.clearance` — String

#### Resource Attributes

Resource properties for SpEL:

- `resource.id` — String
- `resource.type` — String
- `resource.market` — String
- `resource.lob` — String
- `resource.geography` — String
- `resource.channel` — String
- `resource.tenant` — String
- `resource.requesterId` — String

#### Environment Attributes

Environment context from `runtimeContext` for SpEL:

- `environment.hour` — Integer (24-hour UTC)
- `environment.riskScore` — Number
- `environment.currentHour` — Integer

## The 9-Rule Decision Chain

Rules are evaluated in strict priority order. The first rule whose `evaluate()` returns a decision short-circuits all lower rules.

| Priority | Rule | Decision Code on DENY | When It Fires |
|---|---|---|---|
| 1 | `ExplicitDenyRule` | `DECISION_EXPLICIT_DENY` | Any matched policy has `effect=DENY` |
| 2 | `MissingBoundaryContextRule` | `DECISION_MISSING_BOUNDARY_CONTEXT` | Required boundary fields missing from request |
| 3 | `BoundaryViolationRule` | `DECISION_BOUNDARY_DENY` | Request boundary doesn't match resource boundary |
| 4 | `DependencyOutageRule` | `DECISION_DEPENDENCY_UNAVAILABLE` | Dependency unhealthy and endpoint is FAIL_CLOSED |
| 5 | `SpelConditionRule` | `SPEL_CONDITION_FAILED` | SpEL expression evaluates to `false` |
| 6 | `ConsistencyTokenRule` | `CONSISTENCY_VIOLATION` | Request token doesn't match latest token |
| 7 | `ReBacRelationshipRule` | `DECISION_REBAC_NO_RELATIONSHIP` | No BFS path exists for required relationship |
| 8 | `AllowRule` | `DECISION_CAVEAT_FAILED` | ALLOW matched but caveat (time/IP/field) fails |
| 9 | `DefaultDenyRule` | `DECISION_DEFAULT_DENY` | No rule produced a decision |

### Precedence Rules

- **Explicit DENY always wins** (Rule 1)
- **Boundary violations cannot be overridden** (Rule 3 fires before any allow)
- **Caveats can downgrade ALLOW to DENY** (Rule 8 sub-evaluators)
- **Default is DENY** (Rule 9)
- **Missing boundary context** is caught before boundary comparison (Rule 2)
- **SpEL conditions** are evaluated before ReBAC (Rule 5 before Rule 7)
- **Consistency tokens** ensure causal consistency (Rule 6)

## Caveats

Caveats are evaluated inside `AllowRule` (priority 8) and can downgrade an ALLOW to DENY.

### Time Window Caveat

Configured via policy field `timeWindow`: `"09:00-17:00 UTC"`

The emulator derives start/end from the `requestTime` in runtime context. The time window is always `09:00-17:00 UTC` on the day of the request.

```json
{
  "timeWindow": "09:00-17:00 UTC",
  "effect": "ALLOW",
  "state": "ACTIVE"
}
```

Pass a `requestTime` in runtime context:
```json
{
  "runtimeContext": {
    "requestTime": "2026-06-24T14:00:00Z"   // 14:00 UTC → inside window → ALLOW
  }
}
```

### Source IP Caveat

Configured via policy field `sourceIpRange`: `"10.0.0.0/8"`

The emulator checks `sourceIp` in runtime context against the CIDR range `10.0.0.0/8`.

```json
{
  "sourceIpRange": "10.0.0.0/8",
  "effect": "ALLOW",
  "state": "ACTIVE"
}
```

```json
{
  "runtimeContext": {
    "sourceIp": "10.0.0.55"     // within 10.0.0.0/8 → caveat passes
  }
}
```

### Combined Caveats

When a policy has both `timeWindow` and `sourceIpRange`, both must pass for ALLOW.

### Field Mask Caveats

Field masks define per-field access levels in the policy's `fieldMasks` array:

```json
{
  "fieldMasks": [
    {"field": "customer.email", "level": "MASK"},
    {"field": "customer.ssn", "level": "NONE"}
  ],
  "effect": "ALLOW",
  "state": "ACTIVE"
}
```

Access levels: `READ` (visible), `MASK` (masked), `NONE` (removed).

Field masks can also come from:
- Policy-level `fieldMasks` in the policy document
- Runtime context `piiClassification` entries (tag-based)
- Runtime context `fieldMasks` entries (field-level ACL)

**Precedence**: Field-level ACL > Tag-based classification > Policy masks.

## Boundary Context

Five orthogonal boundary dimensions scope every authorization decision:

| Dimension | Example Values |
|---|---|
| `tenant` | `"acme"`, `"tenant-a"`, `"tenant-b"` |
| `geography` | `"us"`, `"EU"`, `"UK"`, `"ap"` |
| `market` | `"retail"`, `"enterprise"`, `"wealth-management"` |
| `lineOfBusiness` | `"cards"`, `"supply-chain"`, `"platform"` |
| `channel` | `"staff"`, `"customer"`, `"system"` |

A policy field set to `"*"` matches any value. An absent field matches all values.

## ReBAC BFS Traversal

The relationship graph is traversed using bounded breadth-first search (BFS) via `InMemoryRelationshipGraphAdapter`.

### How It Works

```
subject (depth 0)
  → intermediate node via ANY edge type (depth 1)
    → intermediate node via ANY edge type (depth 2)
      → target resource via REQUIRED edge type (depth 3) → ALLOW
```

Key characteristics:
- **Max depth**: 3 hops (configurable)
- **Type filtering**: Only the direct edge from the subject (depth 0) to the first intermediate node is type-filtered against the required relationship type
- **Intermediate edges**: Do NOT need to match the target relationship type
- **Expired edges**: Edges with `expiresAt` in the past are skipped
- **Bidirectional**: BFS follows both `subjectId→resourceId` and `resourceId→subjectId` edges

### Example: 3-Hop Chain

```
Relationship edges:
  carol → dept-eng  (type=manages)
  dept-eng → div-product  (type=parent)
  div-product → ORD-003  (type=belongs_to)

BFS traversal:
  carol (depth 0)
    → dept-eng (depth 1, via manages)
      → div-product (depth 2, via parent)
        → ORD-003 (depth 3, via belongs_to) → ALLOW
```

## Test Data Categories

Test data is organized under `emulator/src/test/resources/test-data/` in 14 categories:

| Category | Directory | Rules Exercised | Scenarios |
|---|---|---|---|
| Precedence | `precedence/` | 1, 8, 9 | Explicit deny, simple allow, default deny |
| Boundaries | `boundaries/` | 2, 3 | Boundary violation, missing context |
| ReBAC | `rebac/` | 7 | Direct/chain/expired relationships |
| SpEL | `spel/` | 5 | Attribute conditions, SoD, risk score |
| Caveats | `caveats/` | 8 (sub) | Time window, source IP |
| Field Masking | `field-masking/` | 8 (sub) | PII masking, tag-based ACL |
| Consistency Tokens | `consistency-tokens/` | 6 | Token matching, stale tokens |
| Workload | `workload/` | All | Service identity patterns |
| Break-Glass | `break-glass/` | All | Emergency override |
| Policy Lifecycle | `policy-lifecycle/` | All | DRAFT vs ACTIVE states |
| Dependency Outage | `dependency-outage/` | 4 | Fail-closed vs fail-open |
| Compliance Matrix | `compliance-matrix/` | 3, 8 | Market + LOB compliance |
| Channel Separation | `channel-separation/` | 3, 8 | Staff vs customer paths |
| Multi-Rule | `multi-rule/` | All | Complex rule interactions |

### Running a Specific Category

```bash
java -jar emulator/target/oac-policy-emulator-cli-0.1.0-SNAPSHOT.jar \
  --test \
  emulator/src/test/resources/test-data/<category>/policies.json \
  emulator/src/test/resources/test-data/<category>/relationships.json \
  emulator/src/test/resources/test-data/<category>/testcases.json
```

### Running All Categories (Shell Script)

```bash
#!/bin/bash
JAR=emulator/target/oac-policy-emulator-cli-0.1.0-SNAPSHOT.jar
DIR=emulator/src/test/resources/test-data
PASS=0
FAIL=0
for cat in "$DIR"/*/; do
  name=$(basename "$cat")
  echo "=== $name ==="
  java -jar "$JAR" --test "$cat/policies.json" "$cat/relationships.json" "$cat/testcases.json"
  if [ $? -eq 0 ]; then
    PASS=$((PASS+1))
  else
    FAIL=$((FAIL+1))
  fi
done
echo "Categories: $PASS passed, $FAIL failed"
```

## Output Format

### Test Mode Output

```
  ✅ <test-name> → <decision> (<decision-code>)   // PASS
  ❌ <test-name> → <decision> (expected: <expected>)
     Decision code: <code>
     Matched policies: [<list>]
     Explanation: <evidence>

=== Results: <N> passed, <M> failed ===
```

Exit code `0` = all passed. Exit code `1` = at least one failed.

### Single Mode Output

```
=== Decision ===
  Decision:       ALLOW|DENY
  Code:           DECISION_*
  Matched:        [policy-list]
  Explanation:    evidence://decision/*
  Field masks:    {field=level, ...}
  Evaluated at:   ISO-8601 timestamp
```

## Decision Codes

| Code | Meaning |
|---|---|
| `DECISION_POLICY_ALLOW` | AllowRule fired with ALLOW (no caveats or caveats passed) |
| `DECISION_EXPLICIT_DENY` | ExplicitDenyRule fired (rule 1) |
| `DECISION_MISSING_BOUNDARY_CONTEXT` | MissingBoundaryContextRule fired (rule 2) |
| `DECISION_BOUNDARY_DENY` | BoundaryViolationRule fired (rule 3) |
| `DECISION_DEPENDENCY_UNAVAILABLE` | DependencyOutageRule fired fail-closed (rule 4) |
| `SPEL_CONDITION_FAILED` | SpelConditionRule fired — expression false (rule 5) |
| `SPEL_EVALUATION_ERROR` | SpelConditionRule fired — expression error (rule 5) |
| `CONSISTENCY_VIOLATION` | ConsistencyTokenRule fired (rule 6) |
| `DECISION_REBAC_NO_RELATIONSHIP` | ReBacRelationshipRule fired — no path found (rule 7) |
| `DECISION_CAVEAT_FAILED` | AllowRule fired but caveat failed (rule 8 sub-evaluator) |
| `DECISION_DEFAULT_DENY` | DefaultDenyRule fired — no match (rule 9) |
| `DECISION_FAIL_OPEN` | Dependency outage with fail-open endpoint (rule 4) |

## Best Practices

1. **Isolate test data**: Each category in its own directory with dedicated policies, relationships, and test cases
2. **Clear test names**: Use descriptive names that indicate the rule being tested and expected outcome
3. **Minimize policies per test**: Only include policies needed for the specific scenario to avoid unexpected matches
4. **Test the boundary**: Include edge cases like expired relationships, outside time windows, and cross-boundary requests
5. **Verify all 9 rules**: Create at least one scenario that exercises each rule in the chain
6. **Start with precedence tests**: Validate Rule 1 (explicit deny) and Rule 9 (default deny) first, as they are the foundation
7. **Use `--single` for debugging**: When a test fails, run the request as `--single` to see the full decision output

## Troubleshooting

### "No policies matched" for expected ALLOW

- Verify policy `state` is `"ACTIVE"` (not `"DRAFT"` or `"VALIDATED"`)
- Check boundary fields match exactly (tenant, geography, market, LOB, channel)
- Check `subjectId`, `action`, and `resourceType` values
- Confirm the policy has no `resourceId` constraint that doesn't match

### "Unexpected DENY with DECISION_REBAC_NO_RELATIONSHIP"

- A non-ReBAC policy might not include boundary fields, while the request includes a ReBAC-only policy that matches but fails the relationship check
- Solution: add a non-ReBAC allow policy without `requiredRelationship` that also matches the request

### "SpEL evaluation error" in output

- Check property names match exactly (e.g., `requesterId` vs `requester_id`)
- Verify the property is accessible via SpEL's property resolver
- Ensure runtime context contains the needed values

### Cross-boundary denial

- Verify every dimension in the boundary context matches the policy's boundary
- Use `"*"` wildcards in policies that should span multiple boundaries
- Confirm `resourceTenant`/`resourceGeography` etc. in runtime context if overriding boundary defaults