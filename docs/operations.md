# Running The Lab

Run all commands in this document from the `multi-idp/` repository root. Live validation uses the OpenShift context selected by `oc`.

## Prepare The Workstation And Cluster

The lab needs an OpenShift cluster with HTTPS routes, serving certificates, persistent storage, and access to the container registries named in the manifests. The agent init containers also download the dependencies in [requirements.txt](../requirements.txt).

Install `oc`, Bash, OpenSSL, and Python with virtual environment support. Your OpenShift account needs permission to manage the two lab namespaces and read their Secrets.

Create the local working directories and Python environment:

```bash
mkdir -p .private evidence
chmod 700 .private
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

The supplied manifests contain cluster-specific hosts, issuer URLs, network ranges, and the `gp3` storage class. Before using another cluster, update [manifests/](../manifests/) and [config/environment.json](../config/environment.json) consistently. The JSON file configures the runner; it does not render or rewrite the manifests.

## Approve The RH User And Deploy

Explicitly approve the RH SSO identity before deployment. Store its stage RH `sub` as one line in `.private/approved-rh-subject`, then restrict its permissions:

```bash
chmod 600 .private/approved-rh-subject
./deploy.sh
```

The configured RH issuer is `https://sso.stage.redhat.com/auth/realms/redhat-external`. Keep the approval file private and outside Git. Refer to [identity approval](concepts.md#approved-identity-and-provenance) for its purpose.

Deployment generates missing Secrets, applies the current manifests and code ConfigMaps, runs the bootstrap Jobs, and waits for the agents. Re-running it updates the deployed application code and revalidates the approved mappings. Existing Secrets are reused.

Realm import occurs on an empty database. Applying a changed realm JSON to an existing database is not a general realm migration mechanism. The bootstrap script checks its configured revision and applies its specific setup operations.

## Start With A Completely Clean Lab

This procedure deletes all resources in both PoC namespaces, including the database claims and generated credentials. Database volume disposal follows the bound volumes' reclaim policy. The new installation generates new credentials, including console passwords.

Keep the local approved subject file so bootstrap can establish the intended identity mapping again. Remove old generated evidence and recreate the lab:

```bash
oc delete namespace multi-idp-internal multi-idp-external --ignore-not-found --wait=true
mkdir -p evidence
find evidence -mindepth 1 -maxdepth 1 -type f -delete
./deploy.sh
```

Wait for deployment to finish, then obtain a fresh RH ID token and run validation. A clean namespace installation does not require the separate reset comparison described below.

## Reset Databases And Validate Recreation

`--reset` recreates the two databases while preserving namespace Secrets and other resources. Capture the current installation before resetting so the runner can compare database claims and signing keys:

```bash
.venv/bin/python tests/run.py environment
./deploy.sh --reset
.venv/bin/python tests/run.py reset
```

The deployment script copies `evidence/installation.json` to `installation-before-reset.json` before deleting database claims. The reset check requires new PVC identities and signing keys, stable issuer URLs, completed bootstrap, and matching realm revisions. Keep that baseline until the comparison finishes.

## Run Validation

Sign in to RH SSO shortly before the run and obtain a new, unused stage ID token. The current acceptance checks require:

- Issuer `https://sso.stage.redhat.com/auth/realms/redhat-external`, audience `cloud-services`, and payload `typ=ID`
- At least five minutes before expiry at the runner preflight
- Token issuance within 15 minutes, and an `auth_time` within 15 minutes of T1 issuance for the primary evidence check

Refreshing a long-running browser session can produce a new token with an older `auth_time`. The runner's evidence check still requires recent authentication. Reusing an assertion after a successful initial grant can trigger replay rejection even when the previous run later failed.

Save the token in `.private/rh-id-token.json` as either a compact JWT or a JSON object containing `id_token`. Do not put it in chat, Git, or command arguments.

```bash
chmod 600 .private/rh-id-token.json
.venv/bin/python tests/run.py
```

If `.private/rh-id-token` also exists, the runner reads that file first. Update that file or remove the obsolete copy before using the JSON file.

The runner supports these phases:

| Phase | Command | What it does |
| --- | --- | --- |
| Environment | `.venv/bin/python tests/run.py environment` | Check installations and write installation evidence |
| Primary flow | `.venv/bin/python tests/run.py e2e` | Check installations, invoke A, and correlate independent evidence |
| Full acceptance | `.venv/bin/python tests/run.py` | Run the primary flow, N1–N20, and the combined audit |
| Reset comparison | `.venv/bin/python tests/run.py reset` | Check installations and compare against the pre-reset baseline |

Use a new ID token for each primary or full invocation. The N1–N20 tests use separate OAuth fixtures and administrative credentials; some temporarily modify lab configuration and restore it. They run after the primary scenario.

Normal acceptance does not require old reset evidence. The current runner reports `resetValidation: "not-run"` when `reset.json` is absent. If a reset report exists, the audit checks that it matches the current installation.

For local tests with real TLS A2A handlers and simulated identity providers, run:

```bash
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v
```

Those local tests do not establish live Keycloak interoperability.

## Read The Evidence

Reports are written under `evidence/` and ignored by Git. Use the run ID printed by the runner to find the corresponding files.

| File | Contents |
| --- | --- |
| `installation.json` | Current deployment, issuer, key, database, and credential-independence checks |
| `flow-<runId>.json` | Agent A response, RH summary, P1/P2, and trust checks |
| `a2a-<runId>.json` | Calls to B and C, their replies, and TC/T3 summaries |
| `primary-<runId>.json` | Correlation with independent agent and Keycloak events |
| `acceptance-<runId>.json` | N1–N20 results and server events |
| `audit-<runId>.json` | Combined positive and negative cases, milestones, and completion status |
| `agent-a.jsonl`, `agent-b.jsonl`, `agent-c.jsonl` | Collected agent logs; these filenames are reused between runs |
| `reset.json` | Result of the explicit reset comparison, when run |

Each P/N result has a name and description. Token summaries use `subjectLabel` for the identity role, `subjectSha256` for the issuer-local subject fingerprint, and `sha256` for the whole token fingerprint. `azp` identifies the OAuth client. Interpret subject hashes together with their issuer.

An early failure can leave only partial evidence. An installation pass alone does not prove agent communication; inspect the primary report and combined audit when present. Clearing local evidence does not reset Keycloak state or its assertion replay cache.

## Open The Admin Consoles

Retrieve each Keycloak route host:

```bash
oc get route rhbk -n multi-idp-internal -o jsonpath='{.spec.host}{"\n"}'
oc get route rhbk -n multi-idp-external -o jsonpath='{.spec.host}{"\n"}'
```

Open `https://<route-host>/admin/master/console/` for the chosen instance. Use username `console-admin` and read its password from the matching namespace:

```bash
oc get secret console-admin -n multi-idp-internal -o go-template='{{index .data "password"}}' | base64 -d
oc get secret console-admin -n multi-idp-external -o go-template='{{index .data "password"}}' | base64 -d
```

Each instance has its own password. Once signed in, select the `internal` or `partner` realm. The account is created at first database startup through `KC_BOOTSTRAP_ADMIN_USERNAME` and `KC_BOOTSTRAP_ADMIN_PASSWORD`. Changing the Secret later does not change the password stored in an existing database.

## Watch Setup And Diagnose Failures

Follow each bootstrap Job for approval checks, identity links, protected attributes, administrative setup, and final verification:

```bash
oc logs -f job/realm-bootstrap-v4 -n multi-idp-internal
oc logs -f job/realm-bootstrap-v4 -n multi-idp-external
```

Keycloak logs show startup, realm import, and grant errors. Agent logs show each request stage and its request ID:

```bash
oc logs -f deployment/rhbk -n multi-idp-internal
oc logs -f deployment/rhbk -n multi-idp-external
oc logs -f deployment/agent-a -c agent -n multi-idp-internal
oc logs -f deployment/agent-c -c agent -n multi-idp-internal
oc logs -f deployment/agent-b -c agent -n multi-idp-external
```

A's stages cover RH validation, the internal grant, both token exchanges, the external grant, and calls to C and B. For a rejected request, correlate the request ID and time with the corresponding Keycloak event. A generic HTTP 403 from A can represent an upstream grant rejection.

During a rollout, select the newest pod explicitly when inspecting logs:

```bash
oc get pods -l app=agent-a -n multi-idp-internal --sort-by=.metadata.creationTimestamp
oc logs -f pod/<newest-pod-name> -c agent -n multi-idp-internal
```

The `dependencies` init container contains package installation logs. For C, use its label in the internal namespace; for B, use `app=agent-b` in `multi-idp-external`.

[Documentation index](INDEX.md).
