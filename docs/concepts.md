# Authorization and Identity Concepts

This page explains the protocol choices and trust boundaries in the lab. The flow uses OAuth 2.0 with two Red Hat build of Keycloak (RHBK) authorization servers.

## Understanding Realm Issuer Audiences

T2 uses the issuer Uniform Resource Locator (URL) of the partner realm in External RHBK as its audience. The external authorization server consumes T2 as a JSON Web Token (JWT) grant to issue T3. For example, a realm at `keycloak.partner.example` uses this audience value:

```json
{
  "aud": "https://keycloak.partner.example/realms/partner"
}
```

The [Identity Chaining draft, Section 2.4.2](https://www.ietf.org/archive/id/draft-ietf-oauth-identity-chaining-17.html#section-2.4.2) says:

> The aud claim MUST identify the authorization server in trust domain B as a valid intended audience of the assertion

The section accepts the receiving server's token endpoint URL or issuer identifier. The external realm URL is its issuer identifier. Section 2.3.3 explains that this binding limits token misuse. Draft 17 is a work in progress. This explanation does not claim that the lab conforms to the full draft.

The official [Keycloak identity-chaining guide](https://www.keycloak.org/securing-apps/oauth-identity-authorization-chaining-across-domains) uses the receiving realm's issuer URL as a client ID, audience mapper value, and token exchange target in Sections 1.1, 1.2, and 1.5. The [internal realm configuration](../realms/internal.json) follows this pattern.

The exchange request parameter `audience` differs from the JWT claim `aud`. Draft Section 2.3.1 defines the request's `resource` value as the authorization server's Uniform Resource Identifier (URI) and its `audience` value as the logical name. The Keycloak guide uses the URL as the registered client name. The draft does not define Keycloak client names.

Draft Section 2.3.3 recommends restricting an assertion to one authorization-server audience. The [Keycloak JWT Authorization Grant](https://www.keycloak.org/securing-apps/jwt-authorization-grant) rejects assertions with multiple audiences. T2 is the assertion sent to External RHBK, and it has one audience. T1 is an Internal RHBK access token with audiences for Agent C and External RHBK. Agent A exchanges T1 to obtain separate tokens for those targets. Refer to the [token map](flow.md#token-and-identity-map).

## Approving an Identity and Tracking Provenance

The `.private/approved-rh-subject` file contains the stable `sub` subject identifier for a Red Hat Single Sign-On (RH SSO) user. Administrators use this file to approve the user. It contains no password or OpenID Connect (OIDC) ID token.

Deployment copies the value to an `approved-pilot` Secret in each namespace. Bootstrap links the approved subject to the internal pilot user, then links the internal user to the external pilot user. Bootstrap sets protected origin attributes before runtime. A submitted token cannot create a link or approve another user.

The flow preserves distinct identities:

| Identity | Representation |
| --- | --- |
| Original Red Hat Single Sign-On user | Approved issuer and subject, reflected in signed origin claims |
| Internal user | Internal pilot subject in T1, TC, and T2 |
| External user | External pilot subject in T3 |
| Agent A OAuth client | `azp=agent-a-internal` or `azp=agent-a-external` |

The authorized party (`azp`) claim identifies the OAuth client. It does not identify the user subject.

Agent B trusts the external issuer's signature over the provenance claims. Agent A checks that the issued origin subject matches the incoming Red Hat Single Sign-On assertion. Agent B does not verify the original assertion's signature. It also cannot detect every change that a trusted external administrator makes to correctly signed origin data.

The Agent-to-Agent (A2A) flow provides trusted transitive provenance. It does not provide cryptographic proof of the full actor chain or identify the process that presents a bearer token. The implementation is in [security.py](../agents/security.py), [Agent A](../agents/agent_a.py), and the [resource agent handler](../agents/server.py).

## JSON Web Token Grant Identity Providers

The `jwt-authorization-grant` Identity Provider type configures a realm to validate signed JWT assertions at its token endpoint. Its settings identify the trusted issuer and signing keys. Keycloak resolves the assertion subject through a pre-established federated identity link. Internal RHBK trusts Red Hat Single Sign-On. External RHBK trusts the internal issuer. This flow does not use a browser login between the Keycloak realms.

Refer to the [Keycloak JWT Authorization Grant guide](https://www.keycloak.org/securing-apps/jwt-authorization-grant) for the provider type and linked-user requirement.

## External Client Authorization

The external `unapproved-agent` test client has the `partner.invoke` scope, whose audience mapper adds `agent-b` to its tokens. It can obtain a token with `aud=agent-b`. Agent B enforces its approved-client policy by requiring `azp=agent-a-external`. Test N8 verifies that Agent B rejects the token from the unapproved client.

External RHBK also checks the incoming assertion's `azp=agent-a-internal`. This check identifies the internal client that created the assertion. The T3 token identifies the client authenticated at External RHBK. The [external realm policy](../realms/external.json) and [Agent B handler](../agents/server.py) implement these checks.

## Preventing Assertion Replay

The configured providers reject assertion reuse. An unexpired Red Hat Single Sign-On ID token that already obtained T1 can fail on a later run. Keycloak records `Token reuse detected` when the replay check rejects the grant.

A run can consume the assertion before a later evidence check fails. Obtain a fresh, unused ID token for each `all` or `e2e` run. The [validation guide](operations.md#running-validation) explains the token age requirements. The [Keycloak JWT grant guide](https://www.keycloak.org/securing-apps/jwt-authorization-grant) describes the default one-time assertion behavior.

[Documentation index](INDEX.md).
