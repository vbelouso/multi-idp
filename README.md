# Cross-IdP Agent PoC

A disposable lab demonstrating Agent-to-Agent (A2A) calls across two independent Red Hat build of Keycloak authorization domains.

Internal Agent A acts for an approved Red Hat SSO user. It calls internal Agent C and external Agent B with tokens issued for each destination. The agents return identity evidence so the user and OAuth client can be traced through the flow.

## Documentation

Start with the [overview and documentation index](docs/INDEX.md).

| Topic | What it explains |
| --- | --- |
| [What We Build](docs/architecture.md) | Components, Keycloak realms, clients, and bootstrap responsibilities |
| [Identity And Agent Flow](docs/flow.md) | Each OAuth step, token, and A2A call |
| [Running The Lab](docs/operations.md) | Deployment, clean rebuilds, tests, console access, and logs |
| [OAuth And Identity Concepts](docs/concepts.md) | Realm URL audiences, identity approval, provenance, and replay protection |

Deployment definitions live in [manifests/](manifests/), realm configuration in [realms/](realms/), agent applications in [agents/](agents/), and validation in [tests/](tests/).
