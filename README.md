# Cross-IdP Agent PoC

Agent A runs as an Internal Deployment. It receives an approved RH SSO ID assertion, obtains T1, invokes C with TC, obtains T2/T3, and invokes B. Administrative bootstrap establishes the approved identity links and protected attributes before runtime.

The PoC demonstrates trusted transitive identity provenance across two independent Red Hat build of Keycloak instances. Agent B validates External Keycloak's signed token and authorization policy. It does not independently verify the original RH SSO authentication event.

The repository contains the runnable lab:

- [Internal Keycloak and PostgreSQL](manifests/internal-keycloak.yaml)
- [External Keycloak and PostgreSQL](manifests/external-keycloak.yaml)
- [Realm bootstrap Jobs](manifests/bootstrap.yaml), using the bundled `kcadm.sh`
- [A, B, and C agent Deployments](manifests/agents.yaml)
- [Internal realm](realms/internal.json), [external realm](realms/external.json), and [protected user profile](realms/user-profile.json)
- [One acceptance runner](tests/run.py), initiating and observing Agent A

`config/environment.json` contains the non-secret hostnames, namespaces, and realm names for the current lab cluster. Update it when using another cluster.

## Deploy

First, explicitly approve the fixed pilot RH identity. Store its stage RH `sub` as one line in `.private/approved-rh-subject`, mode `0600`. The issuer is fixed to `https://sso.stage.redhat.com/auth/realms/redhat-external`. This administrative approval is separate from the runtime ID token; submitting a token never creates approval.

Run one command from the repository root. It creates both namespaces, generates their independent Secrets, applies the manifests, establishes the approved pilot links and attributes through the existing bootstrap Job, and waits for the agents. It copies only A's two OAuth client secrets into the internal namespace. A receives neither provisioner credentials nor a Kubernetes API token. Secret values stay out of manifests, command arguments, and terminal output. The checked-in hosts target the current lab cluster. Change the hosts, issuer URLs, and storage class for another cluster. Images are pinned by digest; RHBK reports `26.6.9.redhat-00002` at runtime.

Use this command to create or update the lab:

```bash
multi-idp/deploy.sh
```

Use `multi-idp/deploy.sh --reset` to recreate both disposable databases while keeping their generated Secrets.

On its first start with an empty database, each Keycloak creates the `console-admin` master-realm bootstrap administrator from `KC_BOOTSTRAP_ADMIN_USERNAME` and `KC_BOOTSTRAP_ADMIN_PASSWORD`, which reads the namespace-local `console-admin` Secret. Keycloak marks this bootstrap account as temporary and displays a warning after login. Keycloak imports the realm JSON with `start --import-realm`; the bootstrap Job configures the protected profile and scoped API service account. Reset the disposable database to change the initial admin password. Restarting Keycloak does not recreate or reset an existing account.

## Watch setup and agent activity

The bootstrap Job logs approved-pilot preflight, linking, and protected-attribute setup, plus service-account login, master admin login, realm revision check, profile update, role assignment, scope setup, and final verification. An idempotent run against an already configured realm logs the service-account login and revision check, then validates/applies the explicit pilot approval; a fresh bootstrap emits the full sequence. Keycloak's own logs show server startup and realm import. Agents A, B, and C emit JSON startup records and one record for each request stage; request records include the request ID, pass/reject reason, and elapsed time. Stage logs do not include passwords or bearer tokens. A also logs each OAuth transition and downstream A2A call, with token hashes and downstream request IDs on completion.

Follow the internal and external bootstrap Jobs:

```bash
oc logs -f job/realm-bootstrap-v4 -n multi-idp-internal
oc logs -f job/realm-bootstrap-v4 -n multi-idp-external
```

Follow each Keycloak and agent process:

```bash
oc logs -f deployment/rhbk -n multi-idp-internal
oc logs -f deployment/rhbk -n multi-idp-external
oc logs -f deployment/agent-a -c agent -n multi-idp-internal
oc logs -f deployment/agent-c -c agent -n multi-idp-internal
oc logs -f deployment/agent-b -c agent -n multi-idp-external
```

The `dependencies` init container logs the agent SDK installation. During a
rollout, list pods to distinguish the new replica from one still terminating:

```bash
oc get pods -l app=agent-c -n multi-idp-internal \
  --sort-by=.metadata.creationTimestamp
oc get pods -l app=agent-b -n multi-idp-external \
  --sort-by=.metadata.creationTimestamp
oc logs -f pod/<newest-pod-name> -c agent -n <namespace>
```

For the local acceptance runner, each P/N case and milestone is printed as it completes. The runner writes the sanitized report under `evidence/`.

## Validate

```bash
python3 -m venv multi-idp/.venv
multi-idp/.venv/bin/pip install -r multi-idp/requirements.txt
multi-idp/.venv/bin/python multi-idp/tests/run.py environment
```

Place a newly issued stage RH SSO `id_token` with at least five minutes remaining in `multi-idp/.private/rh-id-token.json`, mode `0600`. The file accepts either the compact JWT or a JSON object with an `id_token` field. The issuer must be `https://sso.stage.redhat.com/auth/realms/redhat-external`, audience `cloud-services`, and payload type `ID`.

```bash
multi-idp/.venv/bin/python multi-idp/tests/run.py
```

The primary test invokes only A. A validates the RH assertion and obtains its internal user context through the unchanged JWT Authorization Grant. Its entry endpoint accepts that assertion for the configured `cloud-services` grant; it does not treat the ID token as a downstream API access token. C and B receive only their target-specific access tokens. No runtime request creates links, updates attributes, or supplies B with an expected identity record.

The runner reads existing links and attributes before and after execution and independently correlates A/B/C logs with both Keycloak event streams. A returns sanitized token summaries and downstream results, never raw T1, TC, T2, or T3. Use `tests/run.py e2e` for this primary scenario alone. The default command then runs N1–N20 as isolated administrative regression probes. These probes obtain a separate T1 fixture, temporarily change lab settings, and restore each change. They do not use or export A's runtime tokens.

Agent B uses the pinned external signature, issuer, audience, approved user and client, scope, permission, and signed provenance claims. No provenance Secret or database is used. The external signature attests the administrator-approved account metadata. B cannot independently detect an external administrator substituting another nonempty RH subject in a correctly signed token; this authority is part of the documented trust boundary. A checks that the issued origin subject matches the incoming RH assertion.

The external `unapproved-agent` client deliberately remains an enabled negative-test fixture. Keycloak supports restricting grant capability and allowed identity providers per client. This fixture shares the audience mapper and can obtain an `agent-b` token; B enforces the approved-client boundary using `azp=agent-a-external`. N8 verifies rejection. The existing assertion claim policy checks the internal client's `azp`, not the authenticated external client's identity. An audience alone is not permission to invoke B. Refer to the [Keycloak JWT Authorization Grant configuration](https://www.keycloak.org/securing-apps/jwt-authorization-grant).

Run local tests with real TLS A2A handlers and simulated identity providers:

```bash
multi-idp/.venv/bin/python -m unittest discover -s multi-idp/tests -p 'test_*.py' -v
```

These local tests do not establish live Keycloak interoperability. Credentials stay under `.private/` or in Kubernetes Secrets; sanitized results go under `evidence/`.

## Open Keycloak

- [Internal Keycloak admin console](https://multi-idp-internal.apps.cn-ai-lab.2vn8.p1.openshiftapps.com/admin/master/console)
- [External Keycloak admin console](https://multi-idp-external.apps.cn-ai-lab.2vn8.p1.openshiftapps.com/admin/master/console)

These links open the `master` realm admin console, where the first-start temporary bootstrap administrator `console-admin` exists. Each instance has a different password in its `console-admin` Secret. Read the current password in your terminal with:

```bash
oc get secret console-admin -n multi-idp-internal \
  -o go-template='{{index .data "password"}}' | base64 -d; echo
oc get secret console-admin -n multi-idp-external \
  -o go-template='{{index .data "password"}}' | base64 -d; echo
```

Open the matching console above and use username `console-admin` with the password from that instance's namespace. From the master console, select the `internal` or `partner` realm to manage it.

## Reset

This command deletes and recreates both lab databases. It preserves generated credentials and canonical issuer URLs.

```bash
multi-idp/deploy.sh --reset
multi-idp/.venv/bin/python multi-idp/tests/run.py reset
```

The reset check requires new PVC identities and signing keys, stable issuer URLs, and successful bootstrap Jobs matching the versioned realm revision.
