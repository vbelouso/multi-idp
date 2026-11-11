# Running the Lab

Run these commands from the `multi-idp/` repository root. Live validation uses the cluster selected by the OpenShift command-line interface (`oc`). The lab runs two Red Hat build of Keycloak (RHBK) instances. Each realm issuer Uniform Resource Locator (URL) identifies its authorization server. The flow uses OAuth 2.0.

## Preparing the Workstation and Cluster

The lab requires an OpenShift cluster with Hypertext Transfer Protocol Secure (HTTPS) routes, serving certificates, persistent storage, and access to the container registries in the manifests. Agent init containers also download dependencies from [requirements.txt](../requirements.txt).

Install `oc`, Bash, OpenSSL, and Python with virtual environment support. Your OpenShift account needs permission to manage both namespaces and read their Secrets.

Create the local directories and Python environment with these commands:

```bash
mkdir -p .private evidence
chmod 700 .private
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

The manifests contain cluster-specific hostnames, issuer URLs, network ranges, and the `gp3` storage class. Before using another cluster, update [manifests/](../manifests/) and [config/environment.json](../config/environment.json) consistently. The JavaScript Object Notation (JSON) file configures the runner. It does not render or rewrite manifests.

## Approving the User and Deploying the Lab

Approve the Red Hat Single Sign-On identity before deployment. Store the stage issuer's `sub` value on one line in `.private/approved-rh-subject`. Then restrict access to the file and deploy the lab:

```bash
chmod 600 .private/approved-rh-subject
./deploy.sh
```

The configured issuer is `https://sso.stage.redhat.com/auth/realms/redhat-external`. Keep the approval file private and outside Git. Refer to [identity approval](concepts.md#approving-an-identity-and-tracking-provenance) for details.

Deployment generates missing Secrets, applies manifests and agent code ConfigMaps, runs bootstrap Jobs, and waits for the agents. When you run the deployment script again, it updates the deployed code and checks the approved identity links. It reuses existing Secrets.

Keycloak imports a realm only when its database is empty. Applying changed realm JSON to an existing database does not migrate the realm. The bootstrap script checks its configured revision and applies its defined setup operations.

## Creating a Clean Lab

The following command deletes both lab namespaces, including database claims and generated credentials. The storage system's reclaim policy determines whether it deletes the database volumes. A new installation generates new credentials, including console passwords.

Keep the approved subject file so bootstrap can recreate the intended identity links. Clear the old reports and generated dashboards, then deploy the lab with these commands:

```bash
oc delete namespace multi-idp-internal multi-idp-external --ignore-not-found --wait=true
mkdir -p evidence
find evidence -mindepth 1 -type f -delete
./deploy.sh
```

After deployment completes, obtain a fresh OpenID Connect (OIDC) ID token from Red Hat Single Sign-On and run validation. A clean installation does not require the separate reset comparison.

## Resetting Databases and Validating Recreation

The `--reset` option recreates both databases while preserving namespace Secrets and other resources. Capture the installation state before the reset so the runner can compare database claims and signing keys:

```bash
.venv/bin/python tests/run.py environment
./deploy.sh --reset
.venv/bin/python tests/run.py reset
```

Before deleting database claims, the deployment script copies `evidence/installation.json` to `evidence/installation-before-reset.json`. The reset check requires new PersistentVolumeClaim (PVC) identities and signing keys. It also checks stable issuer URLs and completed bootstrap. Keep the baseline until the comparison finishes.

## Running Validation

Sign in to Red Hat Single Sign-On shortly before the run. Obtain a new, unused stage ID token. The acceptance checks require the following token properties:

- The issuer is `https://sso.stage.redhat.com/auth/realms/redhat-external`, the audience is `cloud-services`, and the payload type is `ID`.
- At runner preflight, the token has at least five minutes before expiration.
- Internal RHBK must issue the first access token (T1) within 15 minutes after the RH SSO token's `iat`. The token's `auth_time` must also be within 15 minutes before T1 issuance.

Refreshing a long-running browser session can produce a new token with an old `auth_time`. A later evidence check can still reject that token. Reuse after a successful grant can also trigger replay rejection, even if a previous run failed later.

Save the token in `.private/rh-id-token.json` as a compact token or as a JSON object with an `id_token` field. Do not put the token in chat, Git, or command arguments. Set the file permissions and run validation with these commands:

```bash
chmod 600 .private/rh-id-token.json
.venv/bin/python tests/run.py
```

If `.private/rh-id-token` also exists, the runner reads that file first. Update it or remove the obsolete copy before using the JSON file.

The runner supports the following phases:

| Phase | Command | Description |
| --- | --- | --- |
| Environment | `.venv/bin/python tests/run.py environment` | Check both installations and write installation evidence |
| Primary flow | `.venv/bin/python tests/run.py e2e` | Check installations, invoke Agent A, and correlate independent evidence |
| Full acceptance | `.venv/bin/python tests/run.py` | Run the primary flow, 20 named regression tests, and the combined audit |
| Reset comparison | `.venv/bin/python tests/run.py reset` | Check installations and compare them with the pre-reset baseline |

Use a new ID token for every primary or full acceptance run. The regression tests use direct OAuth grants and resource-server requests. The runner uses administrative credentials to configure and inspect them. Some tests temporarily modify lab settings and restore them after each test.

Normal acceptance does not require reset evidence. If `reset.json` is absent, the runner records `resetValidation: "not-run"`. If the report exists, the audit checks that it matches the current installation.

For local tests with real Transport Layer Security (TLS) handlers that use the Agent-to-Agent (A2A) protocol and simulated identity providers, run this command:

```bash
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v
```

These local tests do not establish live Keycloak interoperability.

## Reading the Evidence

The runner writes reports under `evidence/`, which Git ignores. Use the run ID printed by the runner to find the matching reports.

| File | Contents |
| --- | --- |
| `installation.json` | Installation, issuer, key, database, and credential-independence checks |
| `flow-<runId>.json` | RH assertion to internal token and internal-to-external token chain |
| `a2a-<runId>.json` | Agent A's calls to Agents B and C, their replies, and TC and T3 summaries |
| `primary-<runId>.json` | Correlation with independent agent logs and Keycloak events |
| `acceptance-<runId>.json` | Names, descriptions, results, and server events for regression tests N1–N20 |
| `audit-<runId>.json` | Positive and negative results, milestones, and completion status |
| `agent-a.jsonl`, `agent-b.jsonl`, `agent-c.jsonl` | Agent logs; the runner replaces these files on each run |
| `reset.json` | Result of the reset comparison, when you run it |

The primary checks have short identifiers in the reports. The flow guide lists the full name and purpose of each check. Every regression result includes a name and description. Token summaries use `subjectLabel` for the identity role, `subjectSha256` for an issuer-local subject fingerprint, and `sha256` for the complete token fingerprint. The `azp` claim identifies the OAuth client. Compare subject fingerprints only within the same issuer.

An early failure can leave partial evidence. An installation pass does not prove that Agent A called Agents B and C. Check the primary report and combined audit when they exist. Clearing local evidence does not reset Keycloak state or its assertion replay cache.

## Viewing the Evidence Dashboard

Generate a dashboard for the newest audit report with this command:

```bash
python3 generate_dashboard.py
```

The generator selects the newest `audit-*.json` file by modification time and writes a self-contained HTML file under `evidence/dashboards/`. Open the printed path in a browser. The generated directory is ignored by Git, and the generator does not modify the audit report.

To use a specific report, provide its path and an output path:

```bash
python3 generate_dashboard.py evidence/audit-RUN_ID.json --output evidence/dashboards/custom.html
```

You can also select **Open another audit file** in the dashboard to inspect a different report without generating another HTML file.

## Opening the Admin Consoles

Retrieve each Keycloak route hostname with these commands:

```bash
oc get route rhbk -n multi-idp-internal -o jsonpath='{.spec.host}{"\n"}'
oc get route rhbk -n multi-idp-external -o jsonpath='{.spec.host}{"\n"}'
```

Open `https://<route-host>/admin/master/console/` for the instance you want to manage. Use the `console-admin` username. Read the password from the matching namespace:

```bash
oc get secret console-admin -n multi-idp-internal -o go-template='{{index .data "password"}}' | base64 -d
oc get secret console-admin -n multi-idp-external -o go-template='{{index .data "password"}}' | base64 -d
```

Each instance has a different password. After you sign in, select the `internal` or `partner` realm. Keycloak creates the account during the first database startup from `KC_BOOTSTRAP_ADMIN_USERNAME` and `KC_BOOTSTRAP_ADMIN_PASSWORD`. Changing a Secret does not change the password in an existing database.

## Watching Setup and Diagnosing Failures

Use manifest labels to select bootstrap, Keycloak, and agent Pods. The selectors avoid generated Pod names. If a stream ends during a rollout, rerun the command to select the replacement Pod:

```bash
oc logs -f -l app=bootstrap --all-pods --tail=-1 --pod-running-timeout=5m \
-c bootstrap -n multi-idp-internal
oc logs -f -l app=bootstrap --all-pods --tail=-1 --pod-running-timeout=5m \
-c bootstrap -n multi-idp-external
```

Keycloak logs report startup, realm import, and grant errors. Agent logs report each request stage and its request ID. Follow the Keycloak and agent logs with these commands:

```bash
oc logs -f -l app=rhbk --all-pods --tail=-1 -c rhbk \
-n multi-idp-internal
oc logs -f -l app=rhbk --all-pods --tail=-1 -c rhbk \
-n multi-idp-external
oc logs -f -l app=agent-a --all-pods --tail=-1 -c agent \
-n multi-idp-internal
oc logs -f -l app=agent-c --all-pods --tail=-1 -c agent \
-n multi-idp-internal
oc logs -f -l app=agent-b --all-pods --tail=-1 -c agent \
-n multi-idp-external
```

Agent A logs each stage: ID token validation, the internal grant, token exchanges, the external grant, and calls to Agents C and B. Correlate a rejected request's ID and time with the matching Keycloak event. A 403 response from Agent A can indicate that an upstream grant failed.

To inspect package-install logs, select the `dependencies` init container on each agent:

```bash
oc logs -l app=agent-a --all-pods --tail=-1 -c dependencies \
-n multi-idp-internal
oc logs -l app=agent-c --all-pods --tail=-1 -c dependencies \
-n multi-idp-internal
oc logs -l app=agent-b --all-pods --tail=-1 -c dependencies \
-n multi-idp-external
```

[Documentation index](INDEX.md).
