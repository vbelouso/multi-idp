"""Initiate real Agent A execution, then run isolated P/N regression probes.

Run from the repository root: multi-idp/.venv/bin/python multi-idp/tests/run.py
"""
import argparse
import base64
import contextlib
import copy
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import uuid
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
from a2a import types
from google.protobuf.json_format import ParseDict

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agents"))
from security import (EXTERNAL_SUB, INTERNAL_SUB, access_token,
                      RH_ISSUER, call_agent, request, summary, verify)

NAMESPACES = {"internal": "multi-idp-internal", "external": "multi-idp-external"}

TEST_DETAILS = {
    "P1": {"name": "RH assertion to internal token", "description":
           "Agent A presents the approved RH SSO ID token to Internal Keycloak and receives T1 for the internal pilot user."},
    "P2": {"name": "Internal to external token chain", "description":
           "Agent A uses internal T1 to obtain T2, then presents T2 to External Keycloak to obtain T3 for Agent B."},
    "P3": {"name": "Agent A calls external Agent B", "description":
           "Agent A sends an A2A identity-check request to B with T3; B validates the External Keycloak token and returns identity evidence."},
    "P4": {"name": "Approved identity provenance", "description":
           "Correlates the approved RH user, internal and external pilot users, Agent A clients, agent logs, Keycloak events, and unchanged preconfigured trust."},
    "P5": {"name": "External client authorization policy", "description":
           "Checks that External Keycloak grants the configured pilot authority and that Agent B rejects an unapproved OAuth client; see N5–N8."},
    "P6": {"name": "Agent A calls internal Agent C", "description":
           "Agent A exchanges T1 for a token targeted to C, sends an A2A identity-check request, and C validates its Internal Keycloak token."},
    "N1": {"name": "B rejects internal tokens", "description":
           "Send internal T1 and T2 to Agent B and verify its external-issuer validation rejects both."},
    "N2": {"name": "B rejects a wrong audience", "description":
           "Issue a token with an audience other than Agent B and verify B rejects the A2A request."},
    "N3": {"name": "Unconfigured issuer is not trusted", "description":
           "Verify a token from an issuer without configured external trust cannot obtain a grant; removing the provider also blocks the grant."},
    "N4": {"name": "Missing identity links do not create users", "description":
           "Remove each pilot federation link in turn and verify grants fail without automatically creating an account."},
    "N5": {"name": "Disabled external user cannot get a grant", "description":
           "Disable the external pilot account and verify External Keycloak denies the authorization grant."},
    "N6": {"name": "Removing the external role blocks new use", "description":
           "Remove the Agent B role, verify a newly issued token is rejected, and confirm an already issued token remains valid until expiry."},
    "N7": {"name": "Disabled client settings block grants", "description":
           "Individually disable the external client, its JWT grant capability, and its allowed provider; verify each grant is denied."},
    "N8": {"name": "B rejects an unapproved OAuth client", "description":
           "Obtain an Agent B audience token with the unapproved client and verify B rejects it based on the authorized client identity."},
    "N9": {"name": "Expired assertions and tokens are rejected", "description":
           "Wait until a short-lived external grant assertion and Agent B access token expire, then verify the grant and A2A request fail."},
    "N10": {"name": "Invalid signatures and algorithms are rejected", "description":
           "Verify grant processing rejects altered signatures, unknown signing keys, unsigned tokens, and an unapproved algorithm."},
    "N11": {"name": "Invalid signed provenance is rejected", "description":
           "Remove required origin data or set an inconsistent internal-user mapping, then verify Agent B rejects each signed token."},
    "N12": {"name": "Runtime tokens cannot edit trust", "description":
           "Use an access token to attempt provenance, federation-link, role, and mapper changes; verify each edit is denied and data is unchanged."},
    "N13": {"name": "A2A metadata cannot replace identity", "description":
           "Send forged identity and client fields in A2A metadata and verify B reports the authenticated token claims instead."},
    "N14": {"name": "JWT grant assertion replay is rejected", "description":
           "Use one T2 assertion for a successful grant, replay it, and verify the second grant is denied."},
    "N15": {"name": "Wrong and multiple audiences are rejected", "description":
           "Verify grants reject a token for another audience and a token carrying more than one audience."},
    "N16": {"name": "Unapproved internal client cannot cross domains", "description":
           "Create an internal assertion under the unapproved client and verify External Keycloak rejects it with an authorized-client policy error."},
    "N17": {"name": "Requested scopes cannot expand authority", "description":
           "Request extra scopes at both authorization servers and verify they are denied or excluded from issued authority."},
    "N18": {"name": "Missing consent blocks external grant", "description":
           "Remove the pilot client's preapproved consent, verify the grant fails, then restore consent and verify the configured grant works."},
    "N19": {"name": "Alternate pilot login paths are disabled", "description":
           "Check interactive, direct-access, service-account, password, and client-credentials paths cannot authenticate either pilot client/user."},
    "N20": {"name": "Unsupported protected A2A operation is denied", "description":
           "Send a valid Agent B token for an unsupported protected operation and verify B denies it without processing the operation."},
}

TOKEN_FIELD_GLOSSARY = {
    "sha256": "SHA-256 fingerprint of the complete compact token; it is not a user identifier.",
    "subjectSha256": "SHA-256 fingerprint of the issuer-local subject (sub); it can correlate tokens from the same issuer without exposing sub.",
    "subjectLabel": "Human-readable role for the subject represented by this token summary.",
    "azp": "OAuth client that obtained the token; in these results it identifies Agent A's client separately from the user.",
}

def command(*args, data=None, check=True):
    result = subprocess.run(args, input=data, text=True, capture_output=True)
    if check and result.returncode:
        # Commands never contain credential values; Kubernetes Secret input is not logged.
        raise RuntimeError(f"{' '.join(args)} failed: {result.stderr[:1200]}")
    return result

def oc_json(*args):
    return json.loads(command("oc", *args, "-o", "json").stdout)

def get_secret(namespace, name):
    result = command("oc", "get", "secret", name, "-n", namespace, "-o", "json", check=False)
    if result.returncode:
        if "NotFound" in result.stderr:
            return None
        raise RuntimeError(result.stderr[:500])
    return {k: base64.b64decode(v).decode() for k, v in json.loads(result.stdout)["data"].items()}

def revision():
    # Preserve the imported realm pin while setup evolves in the versioned Job.
    sources = sorted((ROOT / "realms").glob("*.json"))
    actual = hashlib.sha256(b"".join(path.read_bytes() for path in sources)).hexdigest()
    if actual != "5180f56a1b9841c90196652c27b7c4a6d6e3e87926fa0f2216de4161c649f1ed":
        raise RuntimeError("Realm JSON changed; update the import revision and source fingerprint")
    return (ROOT / "realms/REVISION").read_text().strip()


def agent_logs(agent):
    side = "external" if agent == "agent-b" else "internal"
    raw = command("oc", "logs", "deployment/" + agent, "-c", "agent", "-n", NAMESPACES[side]).stdout
    entries = [json.loads(line) for line in raw.splitlines() if line.startswith("{")]
    (ROOT / "evidence" / f"{agent}.jsonl").write_text("".join(json.dumps(e) + "\n" for e in entries))
    return entries


def agent_url(agent):
    return f"https://{agent}.{environment()['domain']}"


def sanitize_event(event):
    details = event.get("details", {})
    record = {k: event.get(k) for k in ["id", "time", "type", "clientId", "error"]}
    record.update(tokenId=details.get("token_id"), upstreamIssuer=details.get("identity_provider_issuer"),
        upstreamSubjectSha256=hashlib.sha256(details.get("identity_provider_user_id", "").encode()).hexdigest(),
        provider=details.get("identity_provider"), grantType=details.get("grant_type"))
    if event.get("userId"):
        record["userSha256"] = hashlib.sha256(event["userId"].encode()).hexdigest()
    record["details"] = {k: details[k] for k in ["scope", "auth_method", "reason", "client_policy_error",
        "client_policy_error_detail"] if k in details}
    return record

def read_rh_token():
    path = ROOT / ".private/rh-id-token"
    if not path.exists():
        path = ROOT / ".private/rh-id-token.json"
    path.chmod(0o600)
    raw = path.read_text().strip()
    if raw.startswith(("{", '"')):
        value = json.loads(raw)
        raw = value["id_token"] if isinstance(value, dict) else value
    if not isinstance(raw, str) or raw.count(".") != 2:
        raise ValueError("Expected a compact RH ID token or a JSON id_token field")
    return raw

def environment():
    return json.loads((ROOT / "config/environment.json").read_text())

def issuer(side):
    config = environment()["instances"][side]
    return f"https://{config['hostname']}/realms/{config['realm']}"

def admin(side):
    config = environment()["instances"][side]
    secret = get_secret(config["namespace"], "credentials")
    base = f"https://{config['hostname']}"
    token = access_token(base, config["realm"], "realm-provisioner", secret["provisioner-secret"])
    return f"{base}/admin/realms/{config['realm']}", token

def private_json(name, data):
    path = ROOT / ".private" / name
    path.parent.mkdir(mode=0o700, exist_ok=True)
    # Open with restrictive permissions before any credential bytes are written.
    import os
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(data, handle)

def grant(side, assertion, *, client=None, scope=None, allowed=(200,)):
    settings = environment()["instances"][side]
    secret = get_secret(settings["namespace"], "credentials")
    client = client or ("agent-a-internal" if side == "internal" else "agent-a-external")
    form = {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion,
            "client_id": client, "client_secret": secret["agent-secret" if client.startswith("agent-a-")
                                                       else "other-agent-secret"]}
    if scope is not None:
        form["scope"] = scope
    return request(issuer(side) + "/protocol/openid-connect/token", method="POST", form=form, allowed=allowed)

def exchange(t1, audience, scope=None, *, allowed=(200,)):
    secret = get_secret(NAMESPACES["internal"], "credentials")
    # RFC 8693 §2.1: form-encoded exchange with a separately authenticated client.
    form = {"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "subject_token": t1,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": audience, "client_id": "agent-a-internal", "client_secret": secret["agent-secret"]}
    if scope is not None:
        form["scope"] = scope
    return request(issuer("internal") + "/protocol/openid-connect/token", method="POST", form=form, allowed=allowed)

def check_environment():
    report = {"utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "instances": {}}
    secrets = {}
    for side, config in environment()["instances"].items():
        ns = config["namespace"]
        resources = oc_json("get", "deployments,pods,pvc,routes,jobs", "-n", ns)["items"]
        deployment = next(r for r in resources if r["kind"] == "Deployment" and r["metadata"]["name"] == "rhbk")
        pods = [r for r in resources if r["kind"] == "Pod" and r["metadata"].get("labels", {}).get("app") == "rhbk"]
        if len(pods) != 1 or not all(c["ready"] for c in pods[0]["status"]["containerStatuses"]):
            raise RuntimeError(f"{side} is not running one healthy replica")
        discovery = request(issuer(side) + "/.well-known/openid-configuration")[1]
        if discovery["issuer"] != issuer(side):
            raise RuntimeError("Issuer mismatch")
        jwks = request(discovery["jwks_uri"])[1]
        thumbprints = []
        for key in jwks["keys"]:
            if key["kty"] == "RSA" and key.get("use") == "sig":
                canonical = json.dumps({field: key[field] for field in ["e", "kty", "n"]},
                                       sort_keys=True, separators=(",", ":"))
                thumbprints.append(hashlib.sha256(canonical.encode()).hexdigest())
        if not thumbprints:
            raise RuntimeError("No RSA signing keys")
        base, token = admin(side)
        realm = request(base, token=token)[1]
        if realm.get("attributes", {}).get("multi-idp-bootstrap") != "complete":
            raise RuntimeError("Bootstrap completion marker is missing")
        if realm["attributes"]["multi-idp-revision"] != revision():
            raise RuntimeError("Live realm revision does not match the current versioned definitions")
        logs = command("oc", "logs", "deployment/rhbk", "-n", ns, "--tail=300").stdout
        version = "26.6.9.redhat-00002"
        if f"Keycloak {version}" not in logs or "Profile prod activated" not in logs:
            raise RuntimeError("Runtime product version/production mode unverified")
        secrets[side] = {"database": get_secret(ns, "database"), "credentials": get_secret(ns, "credentials")}
        pvc = next(r for r in resources if r["kind"] == "PersistentVolumeClaim" and r["metadata"]["name"] == "data-database-0")
        route = next(r for r in resources if r["kind"] == "Route" and r["metadata"]["name"] == "rhbk")
        jobs = [r for r in resources if r["kind"] == "Job" and r["metadata"].get("labels", {}).get("app") == "bootstrap"]
        if not any(j.get("status", {}).get("succeeded") == 1 for j in jobs):
            raise RuntimeError("No completed bootstrap Job")
        report["instances"][side] = {"namespace": ns, "issuer": discovery["issuer"], "realm": config["realm"],
            "runtimeVersion": version, "productionMode": True, "tlsVerified": True,
            "routeTermination": route["spec"]["tls"]["termination"],
            "requestedImage": deployment["spec"]["template"]["spec"]["containers"][0]["image"],
            "runningImage": pods[0]["status"]["containerStatuses"][0]["imageID"],
            "databasePvcUid": pvc["metadata"]["uid"], "signingKeyThumbprints": sorted(thumbprints),
            "bootstrapRevision": realm["attributes"]["multi-idp-revision"],
            "bootstrapJobs": [{"name": j["metadata"]["name"], "succeeded": j.get("status", {}).get("succeeded", 0)} for j in jobs]}
    a, b = report["instances"].values()
    report["independence"] = {
        "namespaces": a["namespace"] != b["namespace"], "issuers": a["issuer"] != b["issuer"],
        "databases": a["databasePvcUid"] != b["databasePvcUid"], "realms": a["realm"] != b["realm"],
        "signingKeys": set(a["signingKeyThumbprints"]).isdisjoint(b["signingKeyThumbprints"]),
        "databaseCredentials": secrets["internal"]["database"]["password"] != secrets["external"]["database"]["password"],
        "adminCredentials": secrets["internal"]["credentials"]["provisioner-secret"] != secrets["external"]["credentials"]["provisioner-secret"],
        "agentCredentials": secrets["internal"]["credentials"]["agent-secret"] != secrets["external"]["credentials"]["agent-secret"]}
    if not all(report["independence"].values()):
        raise RuntimeError("Instance independence failed")
    path = ROOT / "evidence/installation.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"installation": "pass", "evidence": str(path)}))

def check_reset():
    baseline_path = ROOT / "evidence/installation-before-reset.json"
    require(baseline_path.exists(),
            "Reset baseline is missing; run tests/run.py environment before deploy.sh --reset")
    before = json.loads(baseline_path.read_text())
    after = json.loads((ROOT / "evidence/installation.json").read_text())
    results = {}
    for side in ["internal", "external"]:
        old, new = before["instances"][side], after["instances"][side]
        results[side] = {
            "databaseRecreated": old["databasePvcUid"] != new["databasePvcUid"],
            "signingKeysRegenerated": set(old["signingKeyThumbprints"]).isdisjoint(new["signingKeyThumbprints"]),
            "stableIssuer": old["issuer"] == new["issuer"],
            "bootstrapComplete": any(job["succeeded"] == 1 for job in new["bootstrapJobs"]),
            "currentRevision": new["bootstrapRevision"],
            "databasePvcUid": new["databasePvcUid"],
            "signingKeyThumbprints": new["signingKeyThumbprints"]}
    passed = all(all(result[key] for key in ["databaseRecreated", "signingKeysRegenerated", "stableIssuer",
                                            "bootstrapComplete"]) for result in results.values())
    report = {"utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "status": "pass" if passed else "fail", "instances": results,
              "command": "multi-idp/deploy.sh --reset; multi-idp/.venv/bin/python multi-idp/tests/run.py reset"}
    path = ROOT / "evidence/reset.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"reset": report["status"], "evidence": str(path)}))
    require(passed, "Reset evidence failed")

def approved_subject():
    subject = (ROOT / ".private/approved-rh-subject").read_text().strip()
    require(bool(subject), "Explicit pilot approval is missing; run administrative setup first")
    return subject


def annotate_token_summaries(value):
    """Add local safe subject labels to agent evidence from older deployments."""
    if isinstance(value, dict):
        if {"sha256", "subjectSha256", "issuer"} <= value.keys():
            token_issuer = value["issuer"]
            if token_issuer == RH_ISSUER:
                value["subjectLabel"] = "approved RH SSO user"
            elif token_issuer == issuer("internal"):
                value["subjectLabel"] = "Internal Keycloak pilot user"
            elif token_issuer == issuer("external"):
                value["subjectLabel"] = "External Keycloak pilot user"
            else:
                value["subjectLabel"] = "unclassified user"
        for child in value.values():
            annotate_token_summaries(child)
    elif isinstance(value, list):
        for child in value:
            annotate_token_summaries(child)


def trust_snapshot():
    """Read existing trust; never repair it during the primary scenario."""
    result = {}
    for side, subject, provider, upstream in [
            ("internal", INTERNAL_SUB, "rh-sso", approved_subject()),
            ("external", EXTERNAL_SUB, "internal", INTERNAL_SUB)]:
        base, token = admin(side)
        links = request(f"{base}/users/{subject}/federated-identity", token=token)[1]
        user = request(f"{base}/users/{subject}", token=token)[1]
        expected = {"origin_issuer": [RH_ISSUER], "origin_sub": [approved_subject()],
                    "internal_sub": [INTERNAL_SUB], "provenance_version": ["1"]}
        require(any(link["identityProvider"] == provider and link["userId"] == upstream for link in links),
                "Preapproved federated link is missing")
        require(all(user.get("attributes", {}).get(k) == v for k, v in expected.items()),
                "Preapproved protected attributes do not match")
        result[side] = {"links": links, "attributes": user.get("attributes", {})}
    return hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()


def run_flow():
    """Primary scenario: only A receives the RH assertion and invokes peers."""
    raw = read_rh_token()
    rh = verify(raw, RH_ISSUER, "cloud-services")
    require(rh["sub"] == approved_subject(), "Submitted RH user is not explicitly approved")
    before = trust_snapshot()
    run = str(uuid.uuid4())
    started = int(time.time() * 1000)
    status, response, evidence = call("agent-a", raw)
    finished = int(time.time() * 1000)
    require(status == 200, f"Agent A execution failed: HTTP {status}")
    output = json.loads(response["result"]["message"]["parts"][0]["text"])
    tokens = output["tokens"]
    origin_hash = hashlib.sha256(rh["sub"].encode()).hexdigest()
    expected_rh = summary(raw, rh)
    actual_rh = output["rh"]
    require({k: v for k, v in actual_rh.items() if k != "subjectLabel"} ==
            {k: v for k, v in expected_rh.items() if k != "subjectLabel"}
            and actual_rh.get("subjectLabel", expected_rh["subjectLabel"]) == expected_rh["subjectLabel"],
            "Agent A used another RH assertion")
    annotate_token_summaries(output)
    response["result"]["message"]["parts"][0]["text"] = json.dumps(output)
    for peer, expected_user, expected_client in [("agent-c", INTERNAL_SUB, "agent-a-internal"),
                                                  ("agent-b", EXTERNAL_SUB, "agent-a-external")]:
        downstream = output["downstream"][peer]
        result = ParseDict(downstream["response"]["result"], types.SendMessageResponse())
        identity = json.loads(result.message.parts[0].text)["identity"]
        require(identity["user"] == expected_user and identity["authorizedClient"] == expected_client
                and identity["originSubjectSha256"] == origin_hash and identity["internalUser"] == INTERNAL_SUB,
                "Downstream identity differs from the approved user/client")
    require(trust_snapshot() == before, "Runtime execution modified approved trust")
    mutations = {}
    for side in ("internal", "external"):
        base, token = admin(side)
        admin_events = request(base + "/admin-events?max=500", token=token)[1]
        mutations[side] = [{"time": e["time"], "operation": e.get("operationType"),
                            "resourceType": e.get("resourceType")} for e in admin_events
                           if started <= e["time"] <= finished]
    require(not any(mutations.values()), "Admin mutation occurred during primary Agent A execution")
    report = {"runId": run, "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "installations": json.loads((ROOT / "evidence/installation.json").read_text())["instances"],
              "rh": summary(raw, rh), "trustUnchanged": True, "runtimeAdminEvents": mutations,
              "agentA": {"response": response, **evidence},
              "tests": {"P1": {**TEST_DETAILS["P1"], "status": "pass", "t1": tokens["t1"]},
                        "P2": {**TEST_DETAILS["P2"], "status": "pass", "t2": tokens["t2"], "t3": tokens["t3"]}}}
    a2a = {"runId": run, "sdkVersion": "1.3.0", "protocolVersion": "1.0",
           "tests": {"P3": {**TEST_DETAILS["P3"], "status": "pass", **output["downstream"]["agent-b"]},
                     "P6": {**TEST_DETAILS["P6"], "status": "pass", **output["downstream"]["agent-c"]}},
           "tc": tokens["tc"], "t3": tokens["t3"], "agentARequestId": evidence["request"]["id"]}
    private_json("session.json", {"runId": run})
    (ROOT / "evidence" / f"flow-{run}.json").write_text(json.dumps(report, indent=2) + "\n")
    (ROOT / "evidence" / f"a2a-{run}.json").write_text(json.dumps(a2a, indent=2) + "\n")
    print(json.dumps({"runId": run, "P1": "pass", "P2": "pass", "P3": "pass", "P6": "pass",
                      "execution": "deployed Agent A", "trustUnchanged": True}), flush=True)

def call(agent, token, *, operation="identity-check", metadata=None):
    expected_issuer = RH_ISSUER if agent == "agent-a" else issuer("external" if agent == "agent-b" else "internal")
    return call_agent(agent, agent_url(agent), expected_issuer, token, operation=operation,
                      metadata=metadata, timeout=180 if agent == "agent-a" else 30)


def require(condition, message):
    if not condition:
        raise AssertionError(message)

class Suite:
    def __init__(self):
        self.session = json.loads((ROOT / ".private/session.json").read_text())
        self.t1 = self.session["t1"]
        self.admin_tokens = {}
        self.report = {"runId": self.session["runId"], "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                       "tests": {}, "sdkVersion": "1.3.0", "protocolVersion": "1.0",
                       "installations": json.loads((ROOT / "evidence/installation.json").read_text())["instances"],
                       "guarantee": "Trusted transitive provenance; azp attributes an authorized OAuth client."}

    def api(self, side, path="", method="GET", payload=None, allowed=(200, 201, 204)):
        cached = self.admin_tokens.get(side)
        if cached is None or cached[2] < time.time():
            base, token = admin(side)
            self.admin_tokens[side] = (base, token, time.time() + 30)
        else:
            base, token, _ = cached
        return request(base + path, method=method, payload=payload, token=token, allowed=allowed)[1]

    def client_path(self, side, name):
        return "/clients/" + self.api(side, "/clients?clientId=" + name)[0]["id"]

    @contextlib.contextmanager
    def changed(self, side, path, mutate):
        original = self.api(side, path)
        altered = copy.deepcopy(original)
        mutate(altered)
        self.api(side, path, "PUT", altered)
        try:
            yield altered
        finally:
            self.api(side, path, "PUT", original)

    def t2(self, scope="partner.invoke"):
        return exchange(self.t1, issuer("external"), scope)[1]["access_token"]

    def t3(self, *, client=None):
        return grant("external", self.t2(), client=client, scope="partner.invoke")[1]["access_token"]

    def denied_grant(self, assertion=None, *, client=None, scope="partner.invoke"):
        assertion = assertion or self.t2()
        status, response = grant("external", assertion, client=client, scope=scope,
                                 allowed=(200, 400, 401, 403))
        require(status != 200 and "access_token" not in response, "Invalid grant produced a token")
        return {"http": status, "oauthError": response.get("error"),
                "credentialSha256": hashlib.sha256(assertion.encode()).hexdigest(),
                "description": response.get("error_description", "")[:500]}

    def rejected_b(self, credential, expected=401, **kwargs):
        status, response, evidence = call("agent-b", credential, **kwargs)
        # Container logs can become visible just after the HTTP response arrives.
        for attempt in range(5):
            appended = [event for event in agent_logs("agent-b")
                        if event.get("requestId") == evidence["request"]["id"]]
            if appended:
                break
            time.sleep(0.5)
        require(status == expected, f"Expected B HTTP {expected}, got {status}")
        require(not any(event.get("event") == "processed" for event in appended), "Rejected operation was processed")
        require(any(event.get("event") == "rejected" for event in appended), "No independent B rejection record")
        return {"http": status, "response": response, "requestId": evidence["request"]["id"],
                "noOperationProcessed": True}

    def events(self, side, since):
        events = self.api(side, "/events?max=500")
        return [sanitize_event(event) for event in events if event["time"] >= since]

    def run(self, name, action):
        start = int(time.time() * 1000)
        context = {"testId": name, **TEST_DETAILS[name],
                   "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   "nonce": str(uuid.uuid4()), "operation": action.__name__}
        try:
            evidence = action()
            self.report["tests"][name] = {**context, "status": "pass", "evidence": evidence,
                "serverEvents": {side: self.events(side, start) for side in ["internal", "external"]}}
            print(name, "pass", flush=True)
        except Exception as error:
            self.report["tests"][name] = {**context, "status": "fail", "error": f"{type(error).__name__}: {error}"}
            print(name, "fail", str(error), flush=True)
        (ROOT / "evidence" / f"acceptance-{self.session['runId']}.json").write_text(
            json.dumps(self.report, indent=2) + "\n")

    def n1(self):
        return {"T1": self.rejected_b(self.t1), "T2": self.rejected_b(self.t2())}

    def n2(self):
        scopes = self.api("external", "/client-scopes")
        scope = next(s for s in scopes if s["name"] == "identity")
        mapper_path = f"/client-scopes/{scope['id']}/protocol-mappers/models"
        mapper = next(m for m in self.api("external", mapper_path) if m["protocolMapper"] == "oidc-audience-mapper")
        with self.changed("external", mapper_path + "/" + mapper["id"],
                          lambda m: m["config"].update({"included.client.audience": "unapproved-agent"})):
            token = self.t3()
        claims = verify(token, issuer("external"), "unapproved-agent")
        return {"signedToken": summary(token, claims), "B": self.rejected_b(token)}

    def n3(self):
        foreign = self.t3()
        verified = verify(foreign, issuer("external"), "agent-b")
        unknown = self.denied_grant(foreign)
        provider = self.api("external", "/identity-provider/instances/internal")
        links = self.api("external", f"/users/{EXTERNAL_SUB}/federated-identity")
        self.api("external", "/identity-provider/instances/internal", "DELETE")
        try:
            absent = self.denied_grant()
        finally:
            self.api("external", "/identity-provider/instances", "POST", provider)
            existing = self.api("external", f"/users/{EXTERNAL_SUB}/federated-identity")
            if not any(link["identityProvider"] == "internal" for link in existing):
                self.api("external", f"/users/{EXTERNAL_SUB}/federated-identity/internal", "POST", links[0])
        return {"unconfiguredIssuer": summary(foreign, verified), "unknownIssuer": unknown, "trustRemoved": absent}

    def n4(self):
        inventory = self.api("external", "/users/count")
        path = f"/users/{EXTERNAL_SUB}/federated-identity/internal"
        link = next(link for link in self.api("external", f"/users/{EXTERNAL_SUB}/federated-identity")
                    if link["identityProvider"] == "internal")
        self.api("external", path, "DELETE")
        try:
            result = self.denied_grant()
            require(inventory == self.api("external", "/users/count"), "An external user was automatically created")
        finally:
            self.api("external", path, "POST", link)
        internal_path = f"/users/{INTERNAL_SUB}/federated-identity/rh-sso"
        internal_link = next(link for link in self.api("internal", f"/users/{INTERNAL_SUB}/federated-identity")
                             if link["identityProvider"] == "rh-sso")
        count = self.api("internal", "/users/count")
        self.api("internal", internal_path, "DELETE")
        try:
            # Isolate missing-link validation from the consumed RH assertion cache.
            with self.changed("internal", "/identity-provider/instances/rh-sso",
                              lambda p: p["config"].update({"jwtAuthorizationGrantAssertionReuseAllowed": "true"})):
                status, response = grant("internal", read_rh_token(), scope="partner.invoke c.invoke",
                                         allowed=(200, 400, 401, 403))
            require(status != 200 and "access_token" not in response,
                    "Unlinked RH identity acquired internal pilot authorization")
            require(count == self.api("internal", "/users/count"), "An internal user was automatically created")
        finally:
            self.api("internal", internal_path, "POST", internal_link)
        return {"grant": result, "accountInventoryUnchanged": True,
                "unlinkedRhGrant": {"http": status, "error": response.get("error")},
                "internalAccountInventoryUnchanged": True}

    def n5(self):
        with self.changed("external", f"/users/{EXTERNAL_SUB}", lambda user: user.update(enabled=False)):
            return self.denied_grant()

    def n6(self):
        path = f"/users/{EXTERNAL_SUB}/role-mappings/realm"
        role = self.api("external", "/roles/invoke-b")
        existing = self.t3()
        self.api("external", path, "DELETE", [role])
        try:
            token = self.t3()
            claims = verify(token, issuer("external"), "agent-b")
            result = self.rejected_b(token, 403)
            oldstatus = call("agent-b", existing)[0]
            require(oldstatus == 200, "Unexpected immediate revocation of locally verified old token")
            return {"freshToken": summary(token, claims), "newTokenResult": result,
                    "existingTokenStillValidUntilExpiry": True}
        finally:
            self.api("external", path, "POST", [role])

    def n7(self):
        path = self.client_path("external", "agent-a-external")
        result = {}
        mutations = {"disabledClient": lambda c: c.update(enabled=False),
                     "disabledCapability": lambda c: c["attributes"].update({"oauth2.jwt.authorization.grant.enabled": "false"}),
                     "disallowedProvider": lambda c: c["attributes"].update({"oauth2.jwt.authorization.grant.idp": ""})}
        for name, mutate in mutations.items():
            with self.changed("external", path, mutate):
                result[name] = self.denied_grant()
        return result

    def n8(self):
        token = self.t3(client="unapproved-agent")
        claims = verify(token, issuer("external"), "agent-b")
        require(claims["azp"] == "unapproved-agent", "Fixture did not use another external client")
        return {"token": summary(token, claims), "B": self.rejected_b(token, 403)}

    def n9(self):
        path = self.client_path("internal", "agent-a-internal")
        with self.changed("internal", path, lambda c: c["attributes"].update({"access.token.lifespan": "10"})):
            expired_assertion = self.t2()
        assertion = verify(expired_assertion, issuer("internal"), issuer("external"))
        path = self.client_path("external", "agent-a-external")
        with self.changed("external", path, lambda c: c["attributes"].update({"access.token.lifespan": "10"})):
            expired_token = self.t3()
        final = verify(expired_token, issuer("external"), "agent-b")
        time.sleep(max(0, max(assertion["exp"], final["exp"]) - time.time() + 1))
        return {"assertionExpiredAt": assertion["exp"], "tokenExpiredAt": final["exp"],
                "assertion": self.denied_grant(expired_assertion), "B": self.rejected_b(expired_token)}

    def n10(self):
        original = self.t2()
        claims = verify(original, issuer("internal"), issuer("external"))
        header = jwt.get_unverified_header(original)
        pieces = original.split(".")
        signature = bytearray(base64.urlsafe_b64decode(pieces[2] + "=" * (-len(pieces[2]) % 4)))
        signature[0] ^= 1
        altered = ".".join([*pieces[:2], base64.urlsafe_b64encode(signature).decode().rstrip("=")])
        fixtures = {"alteredSignature": altered,
                    "unknownKey": jwt.encode({**claims, "jti": str(uuid.uuid4())},
                        rsa.generate_private_key(public_exponent=65537, key_size=2048),
                        algorithm="RS256", headers={"kid": "untrusted-fixture-key"}),
                    "unsigned": jwt.encode({**claims, "jti": str(uuid.uuid4())}, "", algorithm="none"),
                    "unapprovedAlgorithm": jwt.encode({**claims, "jti": str(uuid.uuid4())},
                        "a-controlled-negative-test-hmac-key-longer-than-thirty-two-bytes", algorithm="HS256",
                        headers={"kid": header["kid"]})}
        return {name: self.denied_grant(fixture) for name, fixture in fixtures.items()}

    def n11(self):
        path = f"/users/{EXTERNAL_SUB}"
        with self.changed("external", path, lambda u: u["attributes"].pop("origin_sub", None)):
            missing_token = self.t3()
            verify(missing_token, issuer("external"), "agent-b")
            missing = self.rejected_b(missing_token, 403)
        with self.changed("external", path, lambda u: u["attributes"].update(internal_sub=["inconsistent-internal-user"])):
            inconsistent_token = self.t3()
            verify(inconsistent_token, issuer("external"), "agent-b")
            inconsistent = self.rejected_b(inconsistent_token, 403)
        return {"missingSignedProvenance": missing, "inconsistentSignedProvenance": inconsistent}

    def n12(self):
        token = self.t3()
        base, _ = admin("external")
        before = self.api("external", f"/users/{EXTERNAL_SUB}")
        profile = self.api("external", "/users/profile")
        protected = [a for a in profile["attributes"] if a["name"] in
                     ["origin_issuer", "origin_sub", "internal_sub", "provenance_version"]]
        require(len(protected) == 4 and all(a["permissions"]["edit"] == ["admin"] for a in protected),
                "Origin attributes are not admin-only")
        targets = [(f"/users/{EXTERNAL_SUB}", "PUT", {"attributes": {"origin_sub": ["fabricated"]}}),
                   (f"/users/{EXTERNAL_SUB}/federated-identity/internal", "DELETE", None),
                   (f"/users/{EXTERNAL_SUB}/role-mappings/realm", "POST", [self.api("external", "/roles/invoke-b")]),
                   (self.client_path("external", "agent-a-external") + "/protocol-mappers/models", "POST",
                    {"name": "fabricated", "protocol": "openid-connect", "protocolMapper": "oidc-hardcoded-claim-mapper"})]
        decisions = []
        for target, method, payload in targets:
            status, _ = request(base + target, method=method, token=token, payload=payload, allowed=(401, 403))
            decisions.append({"resource": target, "http": status})
        after = self.api("external", f"/users/{EXTERNAL_SUB}")
        require(before.get("attributes") == after.get("attributes"), "Denied mutation changed provenance")
        return {"adminOnlyProfile": True, "deniedEdits": decisions, "provenanceUnchanged": True}

    def n13(self):
        status, response, _ = call("agent-b", self.t3(), metadata={"origin_sub": "fabricated",
                                  "agent": "other-agent", "azp": "administrator"})
        require(status == 200, "Metadata changed otherwise authorized operation")
        identity = json.loads(response["result"]["message"]["parts"][0]["text"])["identity"]
        require(identity["user"] == EXTERNAL_SUB and identity["authorizedClient"] == "agent-a-external",
                "Message metadata overrode authenticated identity")
        return {"http": status, "authenticatedIdentity": identity, "metadataIgnoredForIdentity": True}

    def n14(self):
        assertion = self.t2()
        claims = verify(assertion, issuer("internal"), issuer("external"))
        first = grant("external", assertion, scope="partner.invoke")[0]
        second = self.denied_grant(assertion)
        return {"assertion": summary(assertion, claims), "firstHttp": first, "replay": second}

    def n15(self):
        wrong = exchange(self.t1, "agent-c", "c.invoke")[1]["access_token"]
        wrong_claims = verify(wrong, issuer("internal"), "agent-c")
        multiple = verify(self.t1, issuer("internal"), issuer("external"), single=False)
        require(isinstance(multiple["aud"], list) and len(multiple["aud"]) > 1, "Fixture lacks multiple audiences")
        return {"wrongAudience": {"signedToken": summary(wrong, wrong_claims), "grant": self.denied_grant(wrong)},
                "multipleAudiences": {"signedToken": summary(self.t1, multiple), "grant": self.denied_grant(self.t1)}}

    def n16(self):
        # Controlled source fixture: permit RH assertion reuse only while creating a real
        # assertion under the other internal registration. Baseline remains single-use.
        provider = "/identity-provider/instances/rh-sso"
        with self.changed("internal", provider,
                          lambda p: p["config"].update({"jwtAuthorizationGrantAssertionReuseAllowed": "true"})):
            assertion = grant("internal", read_rh_token(), client="unapproved-agent",
                              scope="partner.invoke")[1]["access_token"]
        claims = verify(assertion, issuer("internal"), issuer("external"))
        require(claims["azp"] == "unapproved-agent", "Another internal client was not exercised")
        decision = self.denied_grant(assertion)
        require("azp" in decision["description"], "The unexpected client claim was not the rejection reason")
        return {"controlledSourceReuseFixture": True, "assertion": summary(assertion, claims),
                "grant": decision}

    def n17(self):
        status, response = exchange(self.t1, issuer("external"), "partner.invoke extra", allowed=(200, 400, 403))
        require(status != 200 and "access_token" not in response, "Internal scope expansion succeeded")
        external = self.denied_grant(scope="partner.invoke extra")
        restricted = self.t2()
        claims = verify(restricted, issuer("internal"), issuer("external"))
        default_token = grant("external", restricted)[1]["access_token"]
        output = verify(default_token, issuer("external"), "agent-b")
        require(set(output.get("scope", "").split()) <= set(claims.get("scope", "").split()),
                "Default external scopes expanded authority")
        return {"internal": {"http": status, "error": response.get("error")}, "external": external,
                "inputScopes": claims.get("scope"), "outputScopes": output.get("scope")}

    def n18(self):
        # The versioned import pre-approves this exact scope. Partial import restores
        # only the disposable pilot account after deliberately revoking its consent.
        approved = self.api("external", f"/users/{EXTERNAL_SUB}/consents")
        require(any(c["clientId"] == "agent-a-external" for c in approved), "No imported consent")
        baseline = self.t3()
        user = self.api("external", f"/users/{EXTERNAL_SUB}")
        user["federatedIdentities"] = self.api("external", f"/users/{EXTERNAL_SUB}/federated-identity")
        user["realmRoles"] = [r["name"] for r in self.api("external", f"/users/{EXTERNAL_SUB}/role-mappings/realm")]
        user["clientConsents"] = [{"clientId": "agent-a-external", "grantedClientScopes": ["partner.invoke"]}]
        self.api("external", f"/users/{EXTERNAL_SUB}/consents/agent-a-external", "DELETE")
        try:
            missing = self.denied_grant()
        finally:
            self.api("external", "/partialImport", "POST", {"ifResourceExists": "OVERWRITE", "users": [user]})
        token = self.t3()
        claims = verify(token, issuer("external"), "agent-b")
        require(claims["sub"] == EXTERNAL_SUB, "Consent restoration changed the pilot subject")
        return {"missingConsent": missing, "approvedConsentRestored": True,
                "restoredGrant": summary(token, claims)}

    def n19(self):
        checks = []
        for side in ["internal", "external"]:
            name = "agent-a-internal" if side == "internal" else "agent-a-external"
            client = self.api(side, self.client_path(side, name))
            require(not client["standardFlowEnabled"] and not client["directAccessGrantsEnabled"]
                    and not client["serviceAccountsEnabled"] and not client.get("implicitFlowEnabled"),
                    "An alternate pilot client login flow is enabled")
            user = INTERNAL_SUB if side == "internal" else EXTERNAL_SUB
            require(not self.api(side, f"/users/{user}/credentials"), "Pilot unexpectedly has local credentials")
            secret = get_secret(NAMESPACES[side], "credentials")
            for grant_type in ["password", "client_credentials"]:
                status, response = request(issuer(side) + "/protocol/openid-connect/token", method="POST",
                    form={"grant_type": grant_type, "client_id": name, "client_secret": secret["agent-secret"],
                          "username": "pilot", "password": "negative-test-only"}, allowed=(200, 400, 401, 403))
                require(status != 200 and "access_token" not in response, "Non-RH entry path issued a pilot token")
                checks.append({"side": side, "entry": grant_type, "http": status, "error": response.get("error")})
        return {"loginPaths": checks, "localCredentialsAbsent": True, "interactiveAndImplicitFlowsDisabled": True}

    def n20(self):
        return self.rejected_b(self.t3(), 403, operation="unsupported-protected-operation")

def run_negative():
    # Isolated regression fixture, after the primary scenario has completed.
    # A never exports its bearer tokens. Obtain a separate T1 for direct probes.
    fixture = Suite.__new__(Suite)
    fixture.admin_tokens = {}
    with fixture.changed("internal", "/identity-provider/instances/rh-sso",
                         lambda p: p["config"].update({"jwtAuthorizationGrantAssertionReuseAllowed": "true"})):
        t1 = grant("internal", read_rh_token(), scope="partner.invoke c.invoke")[1]["access_token"]
    session = json.loads((ROOT / ".private/session.json").read_text())
    session["t1"] = t1
    private_json("session.json", session)
    suite = Suite()
    # N16 needs the original RH assertion; exercise it before the expiry test.
    for number in [16, *range(1, 16), *range(17, 21)]:
        suite.run(f"N{number}", getattr(suite, f"n{number}"))
    passed = sum(t["status"] == "pass" for t in suite.report["tests"].values())
    print(f"{passed}/20 negative cases passed")
    return passed == 20

def events(side, client):
    base, token = admin(side)
    raw = request(base + f"/events?client={client}&max=500", token=token)[1]
    return [sanitize_event(event) for event in raw]

def primary_checks(flow, a2a):
    provenance = {"origin_sub": approved_subject(), "version": "1"}
    internal, external = events("internal", "agent-a-internal"), events("external", "agent-a-external")
    checks = {"primaryTrustUnchanged": flow["trustUnchanged"],
              "noRuntimeAdminMutations": not any(flow["runtimeAdminEvents"].values())}
    for side, subject, provider, upstream in [("internal", INTERNAL_SUB, "rh-sso", provenance["origin_sub"]),
                                               ("external", EXTERNAL_SUB, "internal", INTERNAL_SUB)]:
        base, token = admin(side)
        links = request(f"{base}/users/{subject}/federated-identity", token=token)[1]
        user = request(f"{base}/users/{subject}", token=token)[1]
        checks[f"{side}Link"] = any(link["identityProvider"] == provider and link["userId"] == upstream for link in links)
        checks[f"{side}ProtectedOrigin"] = (user.get("attributes", {}).get("origin_sub") == [provenance["origin_sub"]]
            and user.get("attributes", {}).get("origin_issuer") == [RH_ISSUER]
            and user.get("attributes", {}).get("internal_sub") == [INTERNAL_SUB]
            and user.get("attributes", {}).get("provenance_version") == [provenance["version"]])
    t1 = flow["tests"]["P1"]["t1"]
    t2 = flow["tests"]["P2"]["t2"]
    t3 = flow["tests"]["P2"]["t3"]
    checks["targetTokenContracts"] = (
        t1["issuer"] == issuer("internal") and t1["azp"] == "agent-a-internal"
        and t2["issuer"] == issuer("internal") and t2["audience"] in (issuer("external"), [issuer("external")])
        and t2["azp"] == "agent-a-internal"
        and t3["issuer"] == issuer("external") and t3["audience"] in ("agent-b", ["agent-b"])
        and t3["azp"] == "agent-a-external"
        and a2a["tc"]["issuer"] == issuer("internal") and a2a["tc"]["audience"] in ("agent-c", ["agent-c"]))
    checks["rhSignatureAndFreshness"] = (flow["rh"]["signatureVerified"] and flow["rh"]["issuer"] == RH_ISSUER
        and t1["issuedAt"] >= flow["rh"]["issuedAt"] and t1["issuedAt"] - flow["rh"]["issuedAt"] <= 900
        and t1["issuedAt"] < flow["rh"]["expires"])
    auth_time = flow["rh"].get("authenticationTime")
    checks["signedRhAuthenticationTime"] = (isinstance(auth_time, int)
        and 0 <= t1["issuedAt"] - auth_time <= 900)
    checks["rhSubjectLink"] = flow["rh"]["subjectSha256"] == hashlib.sha256(provenance["origin_sub"].encode()).hexdigest()
    checks["internalGrantEvent"] = any(event["tokenId"] == t1["jti"] and not event["error"]
        and event["upstreamIssuer"] == RH_ISSUER and event["upstreamSubjectSha256"] == flow["rh"]["subjectSha256"]
        for event in internal)
    checks["internalExchangeEvent"] = any(event["tokenId"] == t2["jti"] and not event["error"] for event in internal)
    checks["externalGrantEvent"] = any(event["tokenId"] == t3["jti"] and not event["error"]
        and event["upstreamSubjectSha256"] == t2["subjectSha256"] for event in external)
    a_logs = agent_logs("agent-a")
    a_request = a2a["agentARequestId"]
    checks["aExecutionEvent"] = any(event.get("event") == "execution" and event.get("requestId") == a_request
        and event.get("tokens", {}).get("t1", {}).get("sha256") == t1["sha256"]
        and event.get("rh", {}).get("sha256") == flow["rh"]["sha256"]
        and event.get("tokens", {}).get("t3", {}).get("sha256") == a2a["t3"]["sha256"] for event in a_logs)
    completed = [event.get("stage") for event in a_logs if event.get("requestId") == a_request
                 and event.get("status") == "passed"]
    ordered = ["internal_rh_grant", "approved_internal_context", "internal_c_exchange", "call_agent_c",
               "internal_partner_exchange", "external_jwt_grant", "call_agent_b"]
    checks["aOAuthAndCallOrder"] = [stage for stage in completed if stage in ordered] == ordered
    c_logs = agent_logs("agent-c")
    checks["cProcessingEvent"] = any(event.get("event") == "processed"
        and event.get("requestId") == a2a["tests"]["P6"]["request"]["id"]
        and event.get("issuer") == issuer("internal") and event.get("authorizedClient") == "agent-a-internal"
        and event.get("credentialSha256") == a2a["tc"]["sha256"] for event in c_logs)
    checks["cExchangeEvent"] = any(event["tokenId"] == a2a["tc"]["jti"] and not event["error"] for event in internal)
    processing = agent_logs("agent-b")
    request_id = a2a["tests"]["P3"]["request"]["id"]
    checks["bProcessingEvent"] = any(event.get("event") == "processed" and event.get("requestId") == request_id
        and event.get("credentialSha256") == a2a["t3"]["sha256"]
        and event.get("issuer") == issuer("external")
        and event.get("authorizedClient") == "agent-a-external" for event in processing)
    checks["bGrantEvent"] = any(event["tokenId"] == a2a["t3"]["jti"] and not event["error"] for event in external)
    checks["distinctUserAndClient"] = t3["azp"] == "agent-a-external" and t3["subjectSha256"] != hashlib.sha256(t3["azp"].encode()).hexdigest()
    return checks, {"internal": internal, "external": external}


def audit_primary():
    run = json.loads((ROOT / ".private/session.json").read_text())["runId"]
    flow = json.loads((ROOT / "evidence" / f"flow-{run}.json").read_text())
    a2a = json.loads((ROOT / "evidence" / f"a2a-{run}.json").read_text())
    checks, independent = primary_checks(flow, a2a)
    report = {"runId": run, "checks": checks, "independentEvents": independent,
              "status": "pass" if all(checks.values()) else "fail",
              "execution": "deployed Agent A invokes deployed C then B"}
    path = ROOT / "evidence" / f"primary-{run}.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"primary": report["status"], "evidence": str(path)}), flush=True)
    require(all(checks.values()), "Independent primary acceptance evidence is incomplete")


def audit():
    session = json.loads((ROOT / ".private/session.json").read_text())
    run = session["runId"]
    flow = json.loads((ROOT / "evidence" / f"flow-{run}.json").read_text())
    a2a = json.loads((ROOT / "evidence" / f"a2a-{run}.json").read_text())
    negative = json.loads((ROOT / "evidence" / f"acceptance-{run}.json").read_text())
    installation = json.loads((ROOT / "evidence/installation.json").read_text())
    reset_path = ROOT / "evidence/reset.json"
    reset = json.loads(reset_path.read_text()) if reset_path.exists() else None
    checks, independent = primary_checks(flow, a2a)
    tests = {**flow["tests"], **a2a["tests"], **negative["tests"]}
    tests["P4"] = {**TEST_DETAILS["P4"], "status": "pass" if all(checks.values()) else "fail", "checks": checks,
                   "approvedRecordVersion": "1",
                   "independentEvents": independent,
                   "guarantee": "Trusted transitive provenance correlated to this controlled run; B verifies only the external signature."}
    tests["P5"] = {**TEST_DETAILS["P5"],
                   "status": "pass" if all(tests.get(case, {}).get("status") == "pass" for case in ["N5", "N6", "N7", "N8"]) else "fail",
                   "evidenceCases": ["N5", "N6", "N7", "N8"],
                   "existingTokenBehavior": "Local JWT verification honors issued authority until token expiry."}
    for test_id, result in tests.items():
        if test_id in TEST_DETAILS:
            result.update(TEST_DETAILS[test_id])
    required = {"M1": ["P1", "P2", "N3", "N4", "N7", "N9", "N10", "N14", "N15"],
                "M2": ["P3", "P6", "N1", "N2", "N9", "N13", "N20"],
                "M3": ["P4", "P5", "N5", "N6", "N8", "N11", "N12", "N16", "N17", "N18", "N19"]}
    milestone_details = {
        "M1": {"name": "Token issuance and trust boundaries", "description":
               "Covers internal and external grant issuance, approved trust, and token validation negatives."},
        "M2": {"name": "A2A agent communication", "description":
               "Covers Agent A calling C and B with target-appropriate tokens and rejection of invalid downstream requests."},
        "M3": {"name": "Identity and authorization policy", "description":
               "Covers trusted transitive identity evidence, external client authorization, and policy boundaries."},
    }
    milestones = {name: {**milestone_details[name],
                         "status": "pass" if all(tests.get(case, {}).get("status") == "pass" for case in cases) else "fail",
                         "requiredTests": cases} for name, cases in required.items()}
    report = {"runId": run, "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "sdkVersion": a2a["sdkVersion"], "protocolVersion": a2a["protocolVersion"],
              "installations": installation["instances"], "tokenFieldGlossary": TOKEN_FIELD_GLOSSARY,
              "tests": tests, "milestones": milestones,
              "milestonesComplete": all(m["status"] == "pass" for m in milestones.values())
                  and all(tests.get(f"N{n}", {}).get("status") == "pass" for n in range(1, 21))}
    environment_checks = {"installationIndependence": all(installation["independence"].values())}
    reset_checks = []
    if reset is not None:
        environment_checks["reset"] = reset["status"] == "pass"
        reset_checks.append(environment_checks["reset"])
        for side, current in installation["instances"].items():
            restored = reset["instances"][side]
            environment_checks[side] = (current["databasePvcUid"] == restored["databasePvcUid"]
                and current["bootstrapRevision"] == restored["currentRevision"]
                and current["signingKeyThumbprints"] == restored["signingKeyThumbprints"])
            reset_checks.append(environment_checks[side])
    report["environmentChecks"] = environment_checks
    if reset is None:
        report["resetValidation"] = "not-run"
    else:
        report["resetValidation"] = "pass" if all(reset_checks) else "fail"
    report["complete"] = report["milestonesComplete"] and all(environment_checks.values())
    path = ROOT / "evidence" / f"audit-{run}.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"milestones": milestones, "complete": report["complete"], "evidence": str(path)}))
    require(report["complete"], "Acceptance audit failed")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=["all", "e2e", "environment", "reset"], default="all", nargs="?")
    phase = parser.parse_args().phase
    if phase in ("all", "e2e"):
        source = verify(read_rh_token(), RH_ISSUER, "cloud-services")
        require(source.get("typ") == "ID" and source["exp"] - time.time() >= 300,
                "A fresh stage RH ID token with at least five minutes remaining is required")
    check_environment()
    if phase == "environment":
        return
    if phase == "reset":
        check_reset()
        return
    run_flow()
    audit_primary()
    if phase == "e2e":
        return
    run_negative()
    audit()


if __name__ == "__main__":
    main()
