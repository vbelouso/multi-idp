# Overview and Documentation Index

This lab shows how agents call services across separate authorization domains while preserving an approved user's identity. A Red Hat Single Sign-On (RH SSO) OpenID Connect (OIDC) ID token starts the flow. Internal Red Hat build of Keycloak (RHBK) establishes the user context. External RHBK issues the token that the external agent accepts.

The implementation runs two independent RHBK installations and three deterministic Agent-to-Agent (A2A) agents. Agent A performs the Open Authorization (OAuth) exchanges and downstream calls. The flow does not require a language model.

## Choose a Topic

Use this table to find the information you need.

| Question | Document |
| --- | --- |
| What runs in each domain, and how does setup establish trust? | [What We Build](architecture.md) |
| What happens after Agent A receives a request? | [Identity and Agent Flow](flow.md) |
| How do you deploy, rebuild, validate, and inspect the lab? | [Running the Lab](operations.md) |
| Why does a token use a realm issuer as its audience, and what does provenance prove? | [Authorization and Identity Concepts](concepts.md) |

## Scope and Evidence

This disposable lab uses standalone Deployments. It does not claim production support. Its identity guarantee is trusted transitive provenance through approved mappings and signed Keycloak claims.

The source code defines the intended behavior. Live agent logs, Keycloak events, and reports under `evidence/` show the results of a particular run. Documentation does not prove that a live run succeeded.

[Return to the README](../README.md).
