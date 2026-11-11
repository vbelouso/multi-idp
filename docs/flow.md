# Identity And Agent Flow

Agent A executes a fixed sequence: obtain the internal context, call C, obtain the external context, then call B. The [implementation](../agents/agent_a.py) performs these operations within A's own process.

## Request And Token Sequence

The following diagram shows token issuance and the two downstream calls.

```text
Approved RH SSO user
    |
    | RH ID token and A2A request
    v
Internal Agent A
    |
    +-- RH ID token --> Internal Keycloak JWT Authorization Grant --> T1
    |
    +-- T1 --> Internal Keycloak Token Exchange --> TC --> Agent C (A2A)
    |
    +-- T1 --> Internal Keycloak Token Exchange --> T2
    |
    +-- T2 --> External Keycloak JWT Authorization Grant --> T3 --> Agent B (A2A)
    |
    v
Results from C and B, with identity evidence
```

The primary test runner initiates the request to A and observes its execution. It does not obtain A's downstream tokens or call C and B in that primary scenario.

1. **Receive the RH assertion.** A validates its signature against the pinned stage RH issuer, audience `cloud-services`, lifetime, and ID token type. This entry endpoint accepts the RH ID token as the assertion for the configured grant.
2. **Obtain T1.** A authenticates as `agent-a-internal` and submits the RH assertion to Internal Keycloak using JWT Authorization Grant. The approved federation link selects the internal pilot account. A checks the resulting user, client, scopes, and signed origin claims.
3. **Call C.** A exchanges T1 for TC with audience `agent-c` and scope `c.invoke`. It validates C's Agent Card and sends an A2A `identity-check` request with TC. C validates the internal token and returns an identity summary and request nonce.
4. **Obtain T2.** A exchanges T1 for an assertion targeted to the External Keycloak realm, with scope `partner.invoke`.
5. **Obtain T3.** A authenticates as `agent-a-external` and presents T2 to External Keycloak using JWT Authorization Grant. The existing internal-to-external user link selects the external pilot account.
6. **Call B and return results.** A validates T3 and B's Agent Card, then sends an A2A request with T3. B checks its external issuer, audience, user, authorized client, scope, permission, and signed provenance. A returns the downstream results and token summaries.

Both grants use `urn:ietf:params:oauth:grant-type:jwt-bearer`. The internal exchanges use `urn:ietf:params:oauth:grant-type:token-exchange`. A2A calls use JSON-RPC `SendMessage` with protocol version `1.0`.

## Token And Identity Map

User subjects and OAuth clients are distinct identities.

| Token | Issuer | User subject | Audience | Authorized client (`azp`) |
| --- | --- | --- | --- | --- |
| RH ID token | Stage RH SSO | Approved RH user | `cloud-services` | `cloud-services` |
| T1 | Internal Keycloak | Internal pilot | `agent-c` and external realm issuer URL | `agent-a-internal` |
| TC | Internal Keycloak | Internal pilot | `agent-c` | `agent-a-internal` |
| T2 | Internal Keycloak | Internal pilot | External realm issuer URL | `agent-a-internal` |
| T3 | External Keycloak | External pilot | `agent-b` | `agent-a-external` |

T1 carries both invocation scopes. TC retains `c.invoke`; T2 and T3 carry `partner.invoke`. Refer to [realm URL audiences](concepts.md#why-the-audience-is-a-realm-url) for the recipient choice.

## What Establishes Success

A successful token endpoint response alone does not establish an A2A call. The runner checks returned messages and nonces, matches token identifiers to both Keycloak event streams, and correlates request IDs with processing logs from A, C, and B.

It also compares approved trust before and after the primary request and checks for administrative mutations during A's execution. A returns token hashes and selected claims rather than raw downstream bearer tokens.

The later N1–N20 probes are separate administrative tests. They use their own OAuth fixtures, temporarily alter lab settings where necessary, and restore those settings. Refer to [running and reading the tests](operations.md#run-validation).

[Documentation index](INDEX.md).
