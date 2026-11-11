# What We Build

The lab runs two separate authorization domains with Red Hat build of Keycloak (RHBK). Each installation has its own namespace, PostgreSQL database, realm, signing keys, and generated credentials. Red Hat Single Sign-On (RH SSO) supplies the approved identity assertion.

## System Components

Each agent uses the Agent-to-Agent (A2A) protocol. The following components perform distinct roles.

| Component | Location | Responsibility |
| --- | --- | --- |
| Internal RHBK and PostgreSQL | `multi-idp-internal`, realm `internal` | Accept the approved RH SSO assertion and issue internal tokens |
| Agent A | `multi-idp-internal` | Obtain tokens, call Agents C and B, and return results |
| Agent C | `multi-idp-internal` | Process an A2A request authorized by Internal RHBK |
| External RHBK and PostgreSQL | `multi-idp-external`, realm `partner` | Accept the internal assertion and issue external tokens |
| Agent B | `multi-idp-external` | Process an A2A request authorized by External RHBK |
| Bootstrap Job | One per namespace | Create approved identity links and protected attributes |
| Acceptance runner | Local workstation | Invoke Agent A, correlate evidence, and run separate regression tests |

The [Keycloak manifests](../manifests/internal-keycloak.yaml) and [external counterpart](../manifests/external-keycloak.yaml) run standalone RHBK containers. They import realms and use PostgreSQL StatefulSets, persistent storage, and Hypertext Transfer Protocol Secure (HTTPS) routes. They enable the JSON Web Token (JWT) Authorization Grant and Standard Token Exchange V2.

The [agent manifests](../manifests/agents.yaml) run Python applications that use the Agent-to-Agent (A2A) software development kit (SDK). Kustomize generates ConfigMaps that contain agent code and pinned dependency requirements. Each agent installs dependencies in an init container and exposes an HTTPS Agent Card and A2A endpoint.

## Realm Registrations

Each realm has an issuer Uniform Resource Locator (URL) that identifies its authorization server. OAuth registrations define callers and token recipients.

| Registration | Realm | Purpose |
| --- | --- | --- |
| `agent-a-internal` | Internal | Agent A's client for the RH SSO grant and internal exchanges |
| `agent-c` | Internal | Audience for calls to Agent C |
| External realm issuer URL | Internal | Audience target for assertions sent to External RHBK |
| `agent-a-external` | External | Agent A's client for the external JWT grant |
| `agent-b` | External | Audience for calls to Agent B |
| `unapproved-agent` | Both | Test client for authorization checks |
| `realm-provisioner` | Both | Administrative setup and test inspection |

The `c.invoke` and `partner.invoke` client scopes carry the required authority. The agents require the matching `invoke-c` and `invoke-b` permissions. Find these settings in the [internal realm](../realms/internal.json) and [external realm](../realms/external.json).

## Administrative Setup

[deploy.sh](../deploy.sh) creates namespace-local Secrets and applies the manifests. On an empty database, Keycloak imports the realm and creates the initial `console-admin` account in the `master` realm from bootstrap environment variables.

The [bootstrap Job](../manifests/bootstrap.yaml) runs [bootstrap.sh](../realms/bootstrap.sh) with the bundled `kcadm.sh` command-line tool. It creates the following identity links:

```text
Approved RH SSO issuer and subject
    -> Internal pilot user
    -> External pilot user
```

The approved subject comes from a local approval file. Bootstrap sets `origin_issuer`, `origin_sub`, `internal_sub`, and `provenance_version` as protected attributes. It rejects a conflicting approved-user link or protected attribute value.

Agent A receives its two OAuth client secrets. Its service account does not mount a Kubernetes application programming interface (API) token. Agent A does not call the administrative API in Keycloak. Agent B validates signed token claims without a provenance Secret created by the test runner.

Refer to the [runtime flow](flow.md) for the token exchanges. Refer to [identity approval and provenance](concepts.md#approving-an-identity-and-tracking-provenance) for the related trust boundaries.

[Documentation index](INDEX.md).
