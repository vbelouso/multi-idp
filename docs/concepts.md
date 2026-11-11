# OAuth And Identity Concepts

These explanations describe the protocol choices and the trust boundaries used by this PoC.

## Why The Audience Is A Realm URL

T2 uses the External Keycloak realm's issuer URL as its `aud` because that authorization server consumes T2 as a JWT grant to issue T3. For example, an external realm hosted at `keycloak.partner.example` would use:

```json
{
  "aud": "https://keycloak.partner.example/realms/partner"
}
```

[Identity Chaining draft-17, Section 2.4.2](https://www.ietf.org/archive/id/draft-ietf-oauth-identity-chaining-17.html#section-2.4.2) states:

> The aud claim MUST identify the authorization server in trust domain B as a valid intended audience of the assertion

The same section specifies the receiving server's token endpoint or issuer identifier as accepted forms. The external realm URL is its issuer identifier. Section 2.3.3 explains that this binding reduces token misuse. Draft-17 is work in progress; this explains the audience choice without claiming full draft conformance for the PoC.

The official [Keycloak chaining guide](https://www.keycloak.org/securing-apps/oauth-identity-authorization-chaining-across-domains) uses the receiving realm's issuer URL as a client ID, an audience mapper value, and the token exchange target in Sections 1.1, 1.2, and 1.5. Our [internal realm](../realms/internal.json) follows that pattern.

The exchange request parameter `audience` and the resulting JWT claim `aud` serve different roles. [Draft-17, Section 2.3.1](https://www.ietf.org/archive/id/draft-ietf-oauth-identity-chaining-17.html#section-2.3.1) defines request `resource` as the authorization server URI and request `audience` as its logical name. Keycloak's documented approach uses the URL as that registered client name. The draft does not prescribe Keycloak client names.

[Draft-17, Section 2.3.3](https://www.ietf.org/archive/id/draft-ietf-oauth-identity-chaining-17.html#section-2.3.3) recommends one authorization server audience for the assertion. [Keycloak's JWT grant processing](https://www.keycloak.org/securing-apps/jwt-authorization-grant) rejects assertions with multiple audiences. T2 has one audience. The initial T1 has both audiences before separate exchanges produce TC and T2; refer to the [token map](flow.md#token-and-identity-map).

## Approved Identity And Provenance

The `.private/approved-rh-subject` file contains the RH user's stable `sub` identifier. It is administrative approval input. It contains neither a password nor an ID token.

Deployment copies the value to an `approved-pilot` Secret in each namespace. Bootstrap links that RH subject to the internal pilot and links the internal pilot to the external pilot. It sets protected origin attributes before runtime. Submitting an arbitrary RH token does not establish a link or approve a user.

The identities remain distinguishable throughout the flow:

| Identity | Representation |
| --- | --- |
| Original RH user | Approved RH issuer and subject; reflected in signed origin claims |
| Internal user | Internal pilot `sub` in T1, TC, and T2 |
| External user | External pilot `sub` in T3 |
| Agent A OAuth client | `azp=agent-a-internal` or `azp=agent-a-external` |

B trusts the external issuer's signature over the provenance claims. A checks that the issued origin subject matches the incoming RH assertion. B does not independently verify the original RH signature or detect every change a trusted external administrator could make to signed origin data.

This is trusted transitive provenance. It does not establish a cryptographic actor chain or identify the physical process presenting a bearer token. The implementation is in [security.py](../agents/security.py), [Agent A](../agents/agent_a.py), and the [resource agent handler](../agents/server.py).

## JWT Grant Identity Providers

The `jwt-authorization-grant` Identity Provider type records issuer and signing-key trust for incoming assertions. The internal realm trusts RH SSO; the external realm trusts the internal issuer. This flow uses pre-established links and token endpoint requests, with no browser login between the two Keycloak realms.

The provider type and linked-user requirement are documented in the [Keycloak JWT Authorization Grant guide](https://www.keycloak.org/securing-apps/jwt-authorization-grant).

## Why The Unapproved Client Can Obtain A Token

The external `unapproved-agent` fixture shares the audience mapper and can obtain an `agent-b` audience token. B enforces its approved-client policy by requiring `azp=agent-a-external`. N8 checks that B rejects the other client.

External Keycloak also checks the incoming assertion's `azp=agent-a-internal`. These are different checks: the assertion names A's internal registration, while T3 names the client authenticated at External Keycloak. The [realm policy](../realms/external.json) and [B handler](../agents/server.py) implement those boundaries.

## Why A Fresh Token Can Still Be Rejected

The configured providers disable assertion reuse. An unexpired RH ID token that already obtained T1 can therefore fail on a later run. Keycloak records `Token reuse detected` when that replay check rejects the grant.

A previous run can consume the assertion before a later evidence check fails. Obtain a fresh, unused ID token for each invocation of `all` or `e2e`, and follow the authentication freshness requirements in [operations](operations.md#run-validation). The [Keycloak JWT grant guide](https://www.keycloak.org/securing-apps/jwt-authorization-grant) describes its default one-time assertion behavior.

[Documentation index](INDEX.md).
