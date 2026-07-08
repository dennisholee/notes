# Policy Specification

A policy is a JSON document stored in the MongoDB `policies` collection. The engine matches policies against a `CheckPermission` request by comparing fields such as `subjectId`, `action`, `resourceType`, and boundary fields (tenant, geography, market, line of business, channel). When a policy matches, its `effect` is evaluated by the rule chain.

## Policy Document Fields

| Field | Type | Required | Description | Example |
|---|---|---|---|---|
| `name` | String | Yes | Unique identifier for the policy | `"POL.RBAC.ACCOUNT.READ.ALLOW.v1"` |
| `state` | String | Yes | Lifecycle state. Only `ACTIVE` policies are evaluated | `"ACTIVE"` |
| `effect` | String | Yes | `ALLOW` or `DENY` | `"ALLOW"` |
| `action` | String | No | Action verb or `*` for any action | `"read"`, `"approve"`, `"*"` |
| `resourceType` | String | No | Resource type or `*` for any type | `"account"`, `"order"`, `"*"` |
| `resourceId` | String | No | Specific resource instance ID | `"acc-1"` |
| `subjectId` | String | No | Subject the policy applies to | `"user-reader"` |
| `subjectType` | String | No | Subject type filter (`human`, `workload`) | `"workload"` |
| `tenant` | String | No | Tenant scope | `"tenant-a"`, `"acme"` |
| `geography` | String | No | Geography scope | `"us"`, `"EU"`, `"*"` |
| `market` | String | No | Market scope | `"retail"`, `"enterprise"` |
| `lineOfBusiness` | String | No | LOB scope | `"cards"`, `"supply-chain"` |
| `channel` | String | No | Channel scope | `"staff"`, `"customer"`, `"system"` |
| `spelCondition` | String | No | SpEL expression evaluated at priority 5 | `"subject.department == 'hr'"` |
| `requiredRelationship` | String | No | ReBAC relationship type evaluated at priority 7 | `"manages"`, `"owner"` |
| `fieldMasks` | Array | No | Field-level access masks | See E12 |
| `timeWindow` | String | No | Business hours caveat | `"09:00-17:00 UTC"` |
| `sourceIpRange` | String | No | Allowed source IP CIDR | `"10.0.0.0/8"` |
| `version` | String | No | Policy version identifier | `"v1"` |

## Matching Rules

- **Subject match**: A policy matches a request if `subjectId` equals the request's subject id, or if `subjectId` is absent (policy applies to all subjects).
- **Action match**: A policy matches if `action` equals the request action, or is `"*"`, or is absent.
- **ResourceType match**: A policy matches if `resourceType` equals the request resource type, or is `"*"`, or is absent.
- **Boundary match**: For each of tenant, geography, market, line of business, and channel, a policy matches if the field equals the request value, or is `"*"`, or is absent.

## Query Flow

1. `MongoPolicyRegistryAdapter` queries the `policies` collection for all `state=ACTIVE` documents matching the request's subject, action, resource type, and boundary context.
2. Matching policies are returned as `List<String>` in format `"POL.<EFFECT>.<NAME>"` with optional suffixes for conditions (`:<spel>`) and ReBAC requirements (`:REBAC.<type>`).
3. The 9-rule chain evaluates matched policies in priority order. See Appendix: Rule Chain Reference.

---

# Policy Examples

Annotated examples derived from the OAC engine's BDD test scenarios. Each example includes the policy document, the runtime context, the expected decision, and an explanation of which rule in the 9-rule chain produces the result.

---

## RBAC Examples

### E1 — Simple RBAC Allow

A user with `id=user-reader` requests read access on account `acc-1` within the correct tenant scope. The baseline ALLOW policy matches subject, action, and resource type.

**Policy document** (stored in MongoDB `policies` collection):
```json
{
  "name": "POL.RBAC.ACCOUNT.READ.ALLOW.v1",
  "effect": "ALLOW",
  "state": "ACTIVE",
  "subjectId": "user-reader",
  "action": "read",
  "resourceType": "account",
  "resourceId": "acc-1",
  "tenant": "tenant-a",
  "geography": "us",
  "market": "retail",
  "lineOfBusiness": "cards",
  "channel": "staff"
}
```

**Prerequisites:** No relationship edges needed. Baseline fixtures seeded.

**CheckPermission request:**
```json
{
  "subject": { "type": "human", "id": "user-reader" },
  "action": "read",
  "resource": { "type": "account", "id": "acc-1" },
  "boundaryContext": {
    "tenant": "tenant-a", "geography": "us",
    "market": "retail", "lineOfBusiness": "cards", "channel": "staff"
  }
}
```

**Result:**

| Decision | Code | Firing Rule |
|---|---|---|
| ALLOW | `DECISION_POLICY_ALLOW` | Rule 8 — `AllowRule` |

**Test:** `features/policy-decision.feature:27`

---

### E2 — Explicit Deny Override

Same user (`user-reader`, read access on `acc-1`) but a global DENY policy exists. Rule 1 fires before Rule 8 can evaluate the ALLOW policy.

**Policy documents:**
```json
[
  {
    "name": "POL.GLOBAL.ACCESS.DENY.v1",
    "effect": "DENY",
    "state": "ACTIVE",
    "subjectId": "user-reader"
  },
  {
    "name": "POL.RBAC.ACCOUNT.READ.ALLOW.v1",
    "effect": "ALLOW",
    "state": "ACTIVE",
    "subjectId": "user-reader",
    "action": "read",
    "resourceType": "account",
    "resourceId": "acc-1",
    "tenant": "tenant-a",
    "geography": "us",
    "market": "retail",
    "lineOfBusiness": "cards",
    "channel": "staff"
  }
]
```

**Result:**

| Decision | Code | Firing Rule |
|---|---|---|
| DENY | `DECISION_EXPLICIT_DENY` | Rule 1 — `ExplicitDenyRule` |

**Test:** `features/policy-decision.feature:15`

---

### E3 — Workload Identity Access

A workload (service account) named `reporting-service` requests `read_aggregate` access. Workload identities use `channel=system` to bypass staff/customer boundary checks.

**Policy document:**
```json
{
  "name": "POL.WORKLOAD.AGGREGATE.ALLOW.v1",
  "effect": "ALLOW",
  "state": "ACTIVE",
  "subjectType": "workload",
  "subjectId": "reporting-service",
  "action": "read_aggregate",
  "resourceType": "order"
}
```

**CheckPermission request:**
```json
{
  "subject": { "type": "workload", "id": "reporting-service" },
  "action": "read_aggregate",
  "resource": { "type": "order", "id": "ORD-789" },
  "boundaryContext": {
    "tenant": "acme", "geography": "*",
    "market": "*", "lineOfBusiness": "*", "channel": "system"
  }
}
```

**Result:**

| Decision | Code | Firing Rule |
|---|---|---|
| ALLOW | `DECISION_POLICY_ALLOW` | Rule 8 — `AllowRule` |

**Test:** `features/policy-decision.feature:282`

---

## ABAC / SpEL Examples

### E4 — Department-Based Access

A compliance auditor requests read access. The policy has a SpEL condition that restricts access to the `compliance` department.

**Policy document:**
```json
{
  "name": "POL.SPEL.ABC123",
  "effect": "ALLOW",
  "state": "ACTIVE",
  "spelCondition": "subject.department == 'compliance'"
}
```

**CheckPermission request:**
```json
{
  "subject": { "type": "human", "id": "auditor-alice", "department": "compliance" },
  "action": "read",
  "resource": { "type": "order", "id": "ORD-001" },
  "boundaryContext": {
    "tenant": "acme", "geography": "EU", "market": "enterprise",
    "lineOfBusiness": "retail", "channel": "staff"
  }
}
```

**SpEL evaluation:** `subject.department` resolves to `"compliance"`. Expression `'compliance' == 'compliance'` is `true`.

**Result:**

| Decision | Code | Firing Rule |
|---|---|---|
| ALLOW | `DECISION_POLICY_ALLOW` | Rule 5 (SpEL passes) → Rule 8 — `AllowRule` |

**Test:** `features/e2e/abac-attribute-conditions.feature:14`

---

### E5 — Separation of Duties (Self-Approval Denied)

Alice works in `trading` and attempts to approve transaction `TXN-001`, which she requested herself. The SpEL condition prevents a subject from approving their own transaction.

**Policy document:**
```json
{
  "name": "POL.SPEL.SOD.APPROVE.v1",
  "effect": "ALLOW",
  "state": "ACTIVE",
  "spelCondition": "subject.id != resource.requesterId"
}
```

**CheckPermission request:**
```json
{
  "subject": { "type": "human", "id": "alice", "department": "trading" },
  "action": "approve",
  "resource": { "type": "transaction", "id": "TXN-001" },
  "runtimeContext": { "requesterId": "alice" },
  "boundaryContext": {
    "tenant": "acme", "geography": "EU", "market": "enterprise",
    "lineOfBusiness": "retail", "channel": "staff"
  }
}
```

**SpEL evaluation:** `subject.id` is `"alice"`, `resource.requesterId` is `"alice"`. Expression `'alice' != 'alice'` is `false`.

**Result:**

| Decision | Code | Firing Rule |
|---|---|---|
| DENY | `SPEL_CONDITION_FAILED` | Rule 5 — `SpelConditionRule` |

**Test:** `features/e2e/separation-of-duties.feature:13`

When `bob-manager` (not alice) sends the same request, the expression `'bob' != 'alice'` is `true`, producing ALLOW.

---

### E6 — Risk Score Threshold

A trader attempts to execute a high-value transaction (`riskScore=85`). The policy only allows transactions with risk score below 70.

**Policy document:**
```json
{
  "name": "POL.SPEL.RISK.v1",
  "effect": "ALLOW",
  "state": "ACTIVE",
  "spelCondition": "environment.riskScore < 70"
}
```

**CheckPermission request:**
```json
{
  "subject": { "type": "human", "id": "trader", "department": "trading" },
  "action": "execute_trade",
  "resource": { "type": "order", "id": "ORD-HIGH" },
  "runtimeContext": { "riskScore": "85" },
  "boundaryContext": {
    "tenant": "acme", "geography": "EU", "market": "enterprise",
    "lineOfBusiness": "retail", "channel": "staff"
  }
}
```

**SpEL evaluation:** `environment.riskScore` resolves to `85` (coerced to Long). Expression `85 < 70` is `false`.

**Result:**

| Decision | Code | Firing Rule |
|---|---|---|
| DENY | `SPEL_CONDITION_FAILED` | Rule 5 — `SpelConditionRule` |

**Test:** `features/e2e/abac-attribute-conditions.feature:37`

---

## ReBAC Examples

### E7 — Direct Relationship

Alice has a direct `manages` relationship to resource `ORD-001`. The policy requires `manages` relationship.

**Policy document:**
```json
{
  "name": "POL.REBAC.ORDER.APPROVE.ALLOW.v1",
  "effect": "ALLOW",
  "state": "ACTIVE",
  "requiredRelationship": "manages"
}
```

**Relationship edges:**
```json
[
  { "subjectId": "alice", "resourceId": "ORD-001", "relationshipType": "manages" }
]
```

**CheckPermission request:**
```json
{
  "subject": { "type": "human", "id": "alice" },
  "action": "approve",
  "resource": { "type": "order", "id": "ORD-001" },
  "boundaryContext": {
    "tenant": "acme", "geography": "EU", "market": "enterprise",
    "lineOfBusiness": "retail", "channel": "staff"
  }
}
```

**BFS traversal:** `alice` (depth 0) → direct check to `ORD-001` with type `manages` → match found → path exists.

**Result:**

| Decision | Code | Firing Rule |
|---|---|---|
| ALLOW | `DECISION_POLICY_ALLOW` | Rule 7 (ReBAC passes) → Rule 8 — `AllowRule` |

**Test:** `features/phase2a/hierarchical-rebac.feature:13`

---

### E8 — 3-Hop Chain (Org Chart Traversal)

The CEO wants to read an order owned by a CSR at the bottom of the management chain. The relationship graph forms a chain: `CEO → VP → Director → CSR → ORD-001`, all via `manages` edges.

**Policy document:**
```json
{
  "name": "POL.REBAC.ORDER.APPROVE.ALLOW.v1",
  "effect": "ALLOW",
  "state": "ACTIVE",
  "requiredRelationship": "manages"
}
```

**Relationship edges:**
```json
[
  { "subjectId": "CEO", "resourceId": "VP", "relationshipType": "manages" },
  { "subjectId": "VP", "resourceId": "Director", "relationshipType": "manages" },
  { "subjectId": "Director", "resourceId": "CSR", "relationshipType": "manages" },
  { "subjectId": "CSR", "resourceId": "ORD-001", "relationshipType": "manages" }
]
```

**CheckPermission request:**
```json
{
  "subject": { "type": "human", "id": "CEO" },
  "action": "read",
  "resource": { "type": "order", "id": "ORD-001" },
  "boundaryContext": {
    "tenant": "acme", "geography": "EU", "market": "enterprise",
    "lineOfBusiness": "retail", "channel": "staff"
  }
}
```

**BFS traversal:**
```
CEO (depth 0)
 → VP (depth 1, via manages)
   → Director (depth 2, via manages)
     → CSR (depth 3, via manages)
       → ORD-001 direct check → match (manages) → path found
```

**Result:**

| Decision | Code | Firing Rule |
|---|---|---|
| ALLOW | `DECISION_POLICY_ALLOW` | Rule 7 (ReBAC passes) → Rule 8 — `AllowRule` |

**Test:** `features/e2e/hierarchical-rebac-graphlookup.feature:13`

---

### E9 — Type Mismatch Denied

Alice has an `approver` relationship to `ORD-001`, but the policy requires `manages`. The BFS traversal finds Alice at depth 0 but the direct edge check against `ORD-001` with type `manages` fails because the actual edge type is `approver`.

**Policy document:**
```json
{
  "name": "POL.REBAC.ORDER.APPROVE.ALLOW.v1",
  "effect": "ALLOW",
  "state": "ACTIVE",
  "requiredRelationship": "manages"
}
```

**Relationship edges:**
```json
[
  { "subjectId": "alice", "resourceId": "ORD-001", "relationshipType": "approver" }
]
```

**CheckPermission request:**
```json
{
  "subject": { "type": "human", "id": "alice" },
  "action": "approve",
  "resource": { "type": "order", "id": "ORD-001" },
  "boundaryContext": {
    "tenant": "acme", "geography": "EU", "market": "enterprise",
    "lineOfBusiness": "retail", "channel": "staff"
  }
}
```

**BFS traversal:** `alice` (depth 0) → direct edge check with type `manages` → no `manages` edge from `alice` to `ORD-001` → no path found.

**Result:**

| Decision | Code | Firing Rule |
|---|---|---|
| DENY | `DECISION_REBAC_NO_RELATIONSHIP` | Rule 7 — `ReBacRelationshipRule` |

**Test:** `features/e2e/hierarchical-rebac-graphlookup.feature:38`

---

## Boundary Examples

### E10 — Cross-Tenant Boundary Denied

A policy scoped to `tenant-a` exists, but the request specifies `boundaryContext.tenant=tenant-b`. Rule 3 fires because the resolved `resourceTenant` (`tenant-a` from the policy's matched boundary) differs from the request boundary.

**Policy document:**
```json
{
  "name": "POL.TENANT.ACME.ALLOW.v1",
  "effect": "ALLOW",
  "state": "ACTIVE"
}
```

(The policy has no explicit tenant field itself. The baseline rule matches it to `tenant-a` via `applyBaselineRules`.)

**CheckPermission request:**
```json
{
  "subject": { "type": "human", "id": "tenant-admin" },
  "action": "read",
  "resource": { "type": "account", "id": "acc-tenant-b" },
  "boundaryContext": {
    "tenant": "tenant-b", "geography": "us",
    "market": "retail", "lineOfBusiness": "cards", "channel": "staff"
  }
}
```

**Result:**

| Decision | Code | Firing Rule |
|---|---|---|
| DENY | `DECISION_BOUNDARY_DENY` | Rule 3 — `BoundaryViolationRule` |

**Test:** `features/e2e/multi-tenancy-isolation.feature:13`

---

### E11 — Cross-Geography Explicit Allow

An auditor from one geography is explicitly allowed to access data in a different geography (`EU`), with a justification recorded. The baseline rule matches `cross-geo-auditor` + `audit` + `EU` and produces ALLOW.

**Policy document (baseline):**
```json
{
  "name": "POL.ALLOW.CROSS.GEO.EXPLICIT.v1",
  "effect": "ALLOW",
  "state": "ACTIVE"
}
```

**CheckPermission request:**
```json
{
  "subject": { "type": "human", "id": "cross-geo-auditor" },
  "action": "audit",
  "resource": { "type": "account", "id": "acc-eu" },
  "runtimeContext": {
    "resourceGeography": "EU",
    "crossGeoJustification": "Sarbanes-Oxley audit Q3 2026"
  },
  "boundaryContext": {
    "tenant": "acme", "geography": "EU", "market": "enterprise",
    "lineOfBusiness": "retail", "channel": "staff"
  }
}
```

**Result:**

| Decision | Code | Firing Rule |
|---|---|---|
| ALLOW | `DECISION_POLICY_ALLOW` | Rule 8 — `AllowRule` |

**Test:** `features/e2e/multi-tenancy-isolation.feature:59`

---

## Field Mask / Caveat Examples

### E12 — PII Masking

A CSR user reads an order. The matching ALLOW policy carries field masks that restrict access to PII fields.

**Policy document:**
```json
{
  "name": "POL.FIELDMASK.ABC123",
  "effect": "ALLOW",
  "state": "ACTIVE",
  "fieldMasks": [
    { "field": "customer.email", "level": "MASK" },
    { "field": "customer.ssn", "level": "NONE" }
  ]
}
```

**CheckPermission request:**
```json
{
  "subject": { "type": "human", "id": "csr-user" },
  "action": "read",
  "resource": { "type": "order", "id": "ORD-789" },
  "boundaryContext": {
    "tenant": "acme", "geography": "EU", "market": "enterprise",
    "lineOfBusiness": "supply-chain", "channel": "staff"
  }
}
```

**Result:**

```json
{
  "decision": "ALLOW",
  "decisionCode": "DECISION_POLICY_ALLOW_WITH_CAVEATS",
  "attributeAccessMap": {
    "fieldAccess": {
      "customer.email": "MASK",
      "customer.ssn": "NONE"
    }
  }
}
```

- `customer.email` → masked (value replaced with `***@***.***`)
- `customer.ssn` → removed from response body

**Test:** `features/policy-decision.feature:164`

---

### E13 — Time Window Caveat Denied

A policy grants access only during business hours (09:00-17:00 UTC). The request arrives at 03:00 UTC, outside the allowed window. The `TimeWindowCaveatEvaluator` returns `false`, downgrading the ALLOW to DENY.

**Policy document:**
```json
{
  "name": "POL.CAVEAT.ABC123",
  "effect": "ALLOW",
  "state": "ACTIVE",
  "timeWindow": "09:00-17:00 UTC"
}
```

**CheckPermission request:**
```json
{
  "subject": { "type": "human", "id": "user-reader" },
  "action": "read",
  "resource": { "type": "account", "id": "acc-1" },
  "runtimeContext": { "requestTime": "2026-06-24T03:00:00Z" },
  "boundaryContext": {
    "tenant": "tenant-a", "geography": "us",
    "market": "retail", "lineOfBusiness": "cards", "channel": "staff"
  }
}
```

**Caveat evaluation:** Request time `03:00` falls outside `09:00-17:00` → `TimeWindowCaveatEvaluator.evaluate()` returns `false`.

**Result:**

| Decision | Code | Firing Rule |
|---|---|---|
| DENY | `DECISION_CAVEAT_FAILED` | Rule 8 — `AllowRule` (caveat sub-evaluator fails) |

**Test:** `features/policy-decision.feature:230`

---

## Appendix: Rule Chain Reference

| Priority | Rule Class | Decision Code on DENY |
|---|---|---|
| 1 | `ExplicitDenyRule` | `DECISION_EXPLICIT_DENY` |
| 2 | `MissingBoundaryContextRule` | `DECISION_MISSING_BOUNDARY_CONTEXT` |
| 3 | `BoundaryViolationRule` | `DECISION_BOUNDARY_DENY` |
| 4 | `DependencyOutageRule` | `DECISION_DEPENDENCY_UNAVAILABLE` |
| 5 | `SpelConditionRule` | `SPEL_CONDITION_FAILED` / `SPEL_EVALUATION_ERROR` |
| 6 | `ConsistencyTokenRule` | `CONSISTENCY_VIOLATION` |
| 7 | `ReBacRelationshipRule` | `DECISION_REBAC_NO_RELATIONSHIP` |
| 8 | `AllowRule` | `DECISION_CAVEAT_FAILED` |
| 9 | `DefaultDenyRule` | `DECISION_DEFAULT_DENY` |