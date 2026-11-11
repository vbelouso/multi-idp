# Overview And Documentation Index

The PoC explores how an agent can call services across independent authorization domains while carrying the identity of an approved user. An RH SSO ID token starts the flow. Internal Keycloak establishes the internal user context, and External Keycloak issues the authority accepted by the external agent.

The implementation consists of two standalone Keycloak installations and three deterministic A2A agents. Agent A performs the OAuth exchanges and downstream calls. No language model is required.

## Reading Order

The documentation is organized by the question you need to answer.

| Question | Document |
| --- | --- |
| What is deployed, and who configures trust? | [What We Build](architecture.md) |
| What happens after the request reaches Agent A? | [Identity And Agent Flow](flow.md) |
| How do I deploy, rebuild, run tests, and inspect failures? | [Running The Lab](operations.md) |
| Why is an audience a realm URL, and what does provenance prove? | [OAuth And Identity Concepts](concepts.md) |

## Scope And Evidence

This is a disposable lab topology using standalone Deployments, with no production support claim. Its identity guarantee is trusted transitive provenance through approved mappings and signed Keycloak claims.

The source defines the intended behavior. A particular live run establishes its results through agent processing logs, Keycloak events, and reports under `evidence/`. Instructions and example values in these documents are not evidence of a successful run.

[Return to README](../README.md).
