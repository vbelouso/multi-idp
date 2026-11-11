# Identity and Agent Flow

An approved Red Hat Single Sign-On (RH SSO) user sends an OpenID Connect (OIDC) ID token to Agent A. Agent A calls Agents C and B with the Agent-to-Agent (A2A) protocol. Internal and external Red Hat build of Keycloak (RHBK) issue tokens for those calls. Agent A uses the JSON Web Token (JWT) Authorization Grant and Token Exchange V2 to obtain them. The [Agent A implementation](../agents/agent_a.py) performs each operation in its own process.

## Request and Token Sequence

This diagram shows how the authorization servers issue tokens and how Agent A calls the other agents.

```text
Approved Red Hat Single Sign-On user
    |
    | ID token and A2A request
    v
Internal Agent A
    |
    +-- ID token --> Internal RHBK JWT Authorization Grant --> T1
    |
    +-- T1 --> Internal RHBK Token Exchange --> TC --> Agent C
    |
    +-- T1 --> Internal RHBK Token Exchange --> T2
    |
    +-- T2 --> External RHBK JWT Authorization Grant --> T3 --> Agent B
    |
    v
Results from Agents C and B, with identity evidence
```

The primary test runner sends an OpenID Connect (OIDC) ID token and a request to Agent A, then observes its execution. It does not obtain Agent A's downstream tokens or call Agents C and B in this scenario. Agent A completes the following steps:

1. **Validate the OIDC ID token.** Agent A checks the signature, issuer, `cloud-services` audience, lifetime, and ID token type against the configured stage issuer.
2. **Obtain T1.** Agent A authenticates as `agent-a-internal` and presents the ID token to Internal RHBK with the JWT Authorization Grant. The approved federation link selects the internal pilot user. Agent A checks the user, client, scopes, and signed origin claims.
3. **Call Agent C.** Agent A exchanges T1 for TC with audience `agent-c` and scope `c.invoke`. It validates Agent C's Agent Card and sends an A2A `identity-check` request with TC. Agent C validates the internal token and returns an identity summary and request nonce.
4. **Obtain T2.** Agent A exchanges T1 for an assertion targeted at the External RHBK realm, with scope `partner.invoke`.
5. **Obtain T3.** Agent A authenticates as `agent-a-external` and presents T2 to External RHBK with the JWT Authorization Grant. The preconfigured identity link selects the external pilot user.
6. **Call Agent B.** Agent A validates T3 and Agent B's Agent Card, then sends an A2A request with T3. Agent B checks the issuer, audience, user, authorized client, scope, permission, and signed provenance. Agent A returns the downstream results and token summaries.

Agent A authenticates two Open Authorization (OAuth) clients. Both grants use `urn:ietf:params:oauth:grant-type:jwt-bearer`. Internal exchanges use `urn:ietf:params:oauth:grant-type:token-exchange`. A2A calls use the `SendMessage` operation with protocol version `1.0`.

## Token and Identity Map

A token's user subject and its authorized OAuth client represent different identities. Each realm has an issuer Uniform Resource Locator (URL) that identifies its authorization server.

| Token | Issuer | User subject | Audience | Authorized client (`azp`) |
| --- | --- | --- | --- | --- |
| RH SSO ID token | Stage RH SSO | Approved RH SSO user | `cloud-services` | `cloud-services` |
| T1 | Internal RHBK | Internal pilot user | `agent-c` and external realm issuer URL | `agent-a-internal` |
| TC | Internal RHBK | Internal pilot user | `agent-c` | `agent-a-internal` |
| T2 | Internal RHBK | Internal pilot user | External realm issuer URL | `agent-a-internal` |
| T3 | External RHBK | External pilot user | `agent-b` | `agent-a-external` |

T1 carries both invocation scopes. TC carries `c.invoke`. T2 and T3 carry `partner.invoke`. Refer to [realm issuer audiences](concepts.md#understanding-realm-issuer-audiences) for an explanation of the recipient value.

## Evidence of Successful Agent Calls

A successful token endpoint response does not prove that an agent call succeeded. The runner checks the returned messages and nonces. It matches token identifiers with events from both Keycloak instances. It also correlates request IDs with processing logs from Agents A, B, and C.

The runner compares the approved trust before and after the primary request. It also checks that Agent A caused no administrative changes. Agent A returns token fingerprints and selected claims, not raw downstream bearer tokens.

The positive checks use short identifiers in the evidence files. The following table explains each check:

| Identifier | Name | What it verifies |
| --- | --- | --- |
| P1 | RH assertion to internal token | Agent A presents the approved ID token to Internal RHBK and receives T1 for the internal pilot user |
| P2 | Internal to external token chain | Agent A uses T1 to obtain T2, then presents T2 to External RHBK and receives T3 for Agent B |
| P3 | Agent A calls external Agent B | Agent B validates T3 and returns identity evidence for the A2A request |
| P4 | Approved identity provenance | The runner correlates the approved user, both pilot users, Agent A's clients, agent logs, Keycloak events, and unchanged trust |
| P5 | External client authorization | External RHBK issues the configured authority, and Agent B rejects an unapproved OAuth client |
| P6 | Agent A calls internal Agent C | Agent C validates the target-specific token and returns identity evidence for the A2A request |

The N1–N20 regression tests run separately after the primary scenario. They use their own OAuth fixtures and administrative credentials. Some tests temporarily change lab settings and restore them. Refer to [test execution and evidence](operations.md#running-validation).

[Documentation index](INDEX.md).
