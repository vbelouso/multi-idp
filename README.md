# Agent Calls Across Identity Providers

This disposable lab shows Agent-to-Agent (A2A) calls across two separate Red Hat build of Keycloak (RHBK) authorization domains.

Internal Agent A acts for an approved Red Hat Single Sign-On user. It calls internal Agent C and external Agent B with tokens made for each target. The agents return identity evidence that distinguishes the user from the Open Authorization (OAuth) clients used by Agent A.

## Project Documentation

Start with the [overview and documentation index](docs/INDEX.md).

| Topic | Description |
| --- | --- |
| [What We Build](docs/architecture.md) | Components, realms, clients, and setup |
| [Identity and Agent Flow](docs/flow.md) | Token exchanges and agent calls |
| [Running the Lab](docs/operations.md) | Deployment, validation, consoles, and logs |
| [Authorization and Identity Concepts](docs/concepts.md) | Realm issuer audiences, approval, provenance, and replay protection |

Deployment definitions are in [manifests/](manifests/). Realm configuration is in [realms/](realms/). Agent applications are in [agents/](agents/). Validation code is in [tests/](tests/).
