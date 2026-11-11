"""Local TLS integration tests with real A/B/C handlers and simulated IdPs.

These tests exercise protocol and policy boundaries, not live Keycloak behavior.
"""
import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import urllib.parse
import urllib.request
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import jwt

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agents"))
import security
import server
from agent_a import AgentAHandler

APPROVED_RH = "approved-rh-fixture"


def signed(key, kid, issuer, subject, audience, **extra):
    now = int(time.time())
    return jwt.encode({"iss": issuer, "sub": subject, "aud": audience, "iat": now,
                       "exp": now + 600, "jti": str(uuid.uuid4()), "typ": "Bearer", **extra},
                      key, algorithm="RS256", headers={"kid": kid})


class SimulatedKeycloak(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def reply(self, status, data):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_GET(self):
        if self.path.endswith("/.well-known/openid-configuration"):
            return self.reply(200, {"issuer": self.server.issuer,
                "jwks_uri": self.server.issuer + "/protocol/openid-connect/certs"})
        if self.path.endswith("/certs"):
            return self.reply(200, {"keys": [self.server.jwk]})
        return self.reply(404, {})

    def do_POST(self):
        form = dict(urllib.parse.parse_qsl(self.rfile.read(int(self.headers["Content-Length"])).decode()))
        self.server.operations.append({"path": self.path, "grant": form.get("grant_type"),
                                       "client": form.get("client_id")})
        side = self.server.side
        if (self.path != f"/realms/{side}/protocol/openid-connect/token"
                or form.get("client_id") != "agent-a-" + ("external" if side == "partner" else side)
                or form.get("client_secret") != side + "-fixture-secret"):
            return self.reply(401, {"error": "invalid_client"})
        if "assertion" in form:
            upstream = security.RH_ISSUER if side == "internal" else self.server.internal_issuer
            aud = "cloud-services" if side == "internal" else self.server.issuer
            assertion = security.verify(form["assertion"], upstream, aud)
            expected = APPROVED_RH if side == "internal" else security.INTERNAL_SUB
            if assertion["sub"] != expected:
                return self.reply(400, {"error": "invalid_grant"})
        else:
            security.verify(form["subject_token"], self.server.issuer,
                            self.server.external_issuer, single=False)
        aud = ([self.server.external_issuer, "agent-c"] if side == "internal" else "agent-b")
        if "audience" in form:
            aud = form["audience"]
        claims = {"azp": form["client_id"], "scope": form["scope"],
                  "permissions": ["invoke-b", "invoke-c"],
                  "origin_issuer": security.RH_ISSUER, "origin_sub": APPROVED_RH,
                  "internal_sub": security.INTERNAL_SUB, "provenance_version": "1"}
        claims.update(self.server.provenance_override)
        subject = security.INTERNAL_SUB if side == "internal" else security.EXTERNAL_SUB
        token = signed(self.server.key, self.server.kid, self.server.issuer, subject, aud, **claims)
        return self.reply(200, {"access_token": token, "token_type": "Bearer"})


class AgentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / ".private").mkdir(exist_ok=True, mode=0o700)
        cls.tmp = tempfile.TemporaryDirectory(dir=ROOT / ".private")
        cls.addClassCleanup(cls.tmp.cleanup)
        work = Path(cls.tmp.name)
        cls.servers = []
        cls.logs = []
        cls.patches = []
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1))
                .not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
                .sign(key, hashes.SHA256()))
        (work / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (work / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        cls.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.tls.load_cert_chain(work / "cert.pem", work / "key.pem")
        opener = urllib.request.build_opener(security.NoRedirect,
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(work / "cert.pem"))))
        for target, value in [("security.HTTP", opener),
                              ("server.emit_log", lambda agent, event, **fields:
                               cls.logs.append({"agent": agent, "event": event, **fields}))]:
            patcher = patch(target, value)
            patcher.start()
            cls.addClassCleanup(patcher.stop)
        cls.ids = {}
        for side in ("internal", "partner"):
            http = cls.new_server(SimulatedKeycloak)
            http.side, http.kid = side, side + "-key"
            http.issuer = http.url + "/realms/" + side
            http.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            http.jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(http.key.public_key()))
            http.jwk.update(kid=http.kid, use="sig", alg="RS256")
            http.operations = []
            http.provenance_override = {}
            cls.ids[side] = http
        for http in cls.ids.values():
            http.internal_issuer = cls.ids["internal"].issuer
            http.external_issuer = cls.ids["partner"].issuer
        cls.rh_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rh_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(cls.rh_key.public_key()))
        rh_jwk.update(kid="rh-key", use="sig", alg="RS256")
        security.KEY_CACHE[security.RH_ISSUER] = (time.monotonic() + 3600, [rh_jwk])
        cls.addClassCleanup(security.KEY_CACHE.clear)
        cls.agents = {}
        for agent in ("agent-b", "agent-c", "agent-a"):
            http = cls.new_server(AgentAHandler if agent == "agent-a" else server.AgentHandler)
            http.agent = agent
            external = agent == "agent-b"
            http.issuer = cls.ids["partner" if external else "internal"].issuer
            http.client = "agent-a-external" if external else "agent-a-internal"
            http.scope = "partner.invoke" if external else "c.invoke"
            http.permission = "invoke-b" if external else "invoke-c"
            if agent == "agent-a":
                http.issuer = security.RH_ISSUER
            cls.agents[agent] = http
        for side in ("internal", "external"):
            (work / (side + "-secret")).write_text(("partner" if side == "external" else side) + "-fixture-secret")
        env = {"INTERNAL_ISSUER": cls.ids["internal"].issuer, "EXTERNAL_ISSUER": cls.ids["partner"].issuer,
               "AGENT_B_URL": cls.agents["agent-b"].url, "AGENT_C_URL": cls.agents["agent-c"].url}
        env_patch = patch.dict(os.environ, env)
        env_patch.start()
        cls.addClassCleanup(env_patch.stop)
        original_read = Path.read_text
        path_patch = patch.object(Path, "read_text", lambda path, *a, **kw:
            original_read(work / path.name if str(path).startswith("/clients/") else path, *a, **kw))
        path_patch.start()
        cls.addClassCleanup(path_patch.stop)

    @classmethod
    def new_server(cls, handler):
        http = ThreadingHTTPServer(("localhost", 0), handler)
        http.url = "https://localhost:" + str(http.server_port)
        http.socket = cls.tls.wrap_socket(http.socket, server_side=True)
        thread = threading.Thread(target=http.serve_forever, daemon=True)
        thread.start()
        cls.addClassCleanup(http.server_close)
        cls.addClassCleanup(http.shutdown)
        cls.servers.append(http)
        return http

    def setUp(self):
        self.logs.clear()
        for http in self.ids.values():
            http.operations.clear()
            http.provenance_override = {}

    def rh(self, sub=APPROVED_RH, **extra):
        return signed(self.rh_key, "rh-key", security.RH_ISSUER, sub,
                      "cloud-services", typ="ID", **extra)

    def call_a(self, token):
        return security.call_agent("agent-a", self.agents["agent-a"].url, security.RH_ISSUER, token)

    def b_token(self, **extra):
        claims = dict(azp="agent-a-external", scope="partner.invoke", permissions=["invoke-b"],
                      origin_issuer=security.RH_ISSUER, origin_sub=APPROVED_RH,
                      internal_sub=security.INTERNAL_SUB, provenance_version="1")
        claims.update(extra)
        http = self.ids["partner"]
        return signed(http.key, http.kid, http.issuer, security.EXTERNAL_SUB, "agent-b", **claims)

    def test_a_invokes_c_then_b_and_returns_no_tokens(self):
        token = self.rh()
        status, response, _ = self.call_a(token)
        self.assertEqual(status, 200)
        output = json.loads(response["result"]["message"]["parts"][0]["text"])
        self.assertEqual(list(output["downstream"]), ["agent-c", "agent-b"])
        self.assertEqual([e["agent"] for e in self.logs if e["event"] == "processed"],
                         ["agent-c", "agent-b", "agent-a"])
        self.assertEqual(len(self.ids["internal"].operations), 3)
        self.assertEqual(len(self.ids["partner"].operations), 1)
        self.assertNotIn(token, json.dumps(response))
        self.assertNotIn("access_token", json.dumps(response))
        self.assertNotIn(APPROVED_RH, json.dumps(response))
        self.assertTrue(all("/admin/" not in op["path"] for http in self.ids.values() for op in http.operations))
        self.assertEqual(output["identity"]["user"], security.INTERNAL_SUB)
        self.assertEqual(output["tokens"]["t3"]["azp"], "agent-a-external")

    def test_unknown_rh_user_never_calls_downstream(self):
        self.assertEqual(self.call_a(self.rh("unknown-rh-subject"))[0], 403)
        self.assertFalse(any(e["event"] == "processed" for e in self.logs))
        self.assertEqual(len(self.ids["partner"].operations), 0)

    def test_invalid_rh_signature_rejected_before_oauth(self):
        token = self.rh()
        parts = token.split(".")
        parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
        self.assertEqual(self.call_a(".".join(parts))[0], 401)
        self.assertFalse(self.ids["internal"].operations)

    def test_a_rejects_external_origin_substitution_before_calling_b(self):
        self.ids["partner"].provenance_override = {"origin_sub": "different-rh-user"}
        self.assertEqual(self.call_a(self.rh())[0], 502)
        self.assertEqual([e["agent"] for e in self.logs if e["event"] == "processed"], ["agent-c"])

    def test_b_requires_approved_client_and_signed_provenance(self):
        http = self.agents["agent-b"]
        for changes in ({"azp": "unapproved-agent"}, {"origin_sub": ""},
                        {"internal_sub": "wrong"}, {"origin_issuer": "https://unknown.example"}):
            with self.subTest(changes=changes):
                status, _, _ = security.call_agent("agent-b", http.url, http.issuer, self.b_token(**changes))
                self.assertEqual(status, 403)
        self.assertFalse(any(e["event"] == "processed" for e in self.logs))

    def test_b_trusts_issuer_attestation_without_provenance_file(self):
        http = self.agents["agent-b"]
        status, response, _ = security.call_agent("agent-b", http.url, http.issuer,
            self.b_token(), metadata={"origin_sub": "fabricated", "azp": "admin"})
        self.assertEqual(status, 200)
        output = json.loads(response["result"]["message"]["parts"][0]["text"])
        self.assertEqual(output["identity"]["authorizedClient"], "agent-a-external")


class ProvenanceTests(unittest.TestCase):
    def test_required_signed_mapping_values(self):
        claims = {"origin_issuer": security.RH_ISSUER, "origin_sub": APPROVED_RH,
                  "internal_sub": security.INTERNAL_SUB, "provenance_version": "1"}
        self.assertTrue(security.valid_provenance(claims))
        for key in claims:
            with self.subTest(missing=key):
                self.assertFalse(security.valid_provenance({k: v for k, v in claims.items() if k != key}))

    def test_origin_subject_is_issuer_attestation_not_a_local_lookup(self):
        claims = {"origin_issuer": security.RH_ISSUER, "origin_sub": "issuer-approved-subject",
                  "internal_sub": security.INTERNAL_SUB, "provenance_version": "1"}
        self.assertTrue(security.valid_provenance(claims))


class BootstrapTests(unittest.TestCase):
    def run_setup(self, origin):
        (ROOT / ".private").mkdir(exist_ok=True, mode=0o700)
        with tempfile.TemporaryDirectory(dir=ROOT / ".private") as directory:
            work = Path(directory)
            (work / "origin-sub").write_text(APPROVED_RH + "\n")
            attrs = {"origin_issuer": [security.RH_ISSUER], "origin_sub": [origin],
                     "internal_sub": [security.INTERNAL_SUB], "provenance_version": ["1"]}
            (work / "user.json").write_text(json.dumps({"attributes": attrs}, indent=2))
            script = (ROOT / "realms/bootstrap.sh").read_text().rsplit('\nmain "$@"', 1)[0]
            script = script.replace("/approval/", directory + "/").replace("/work/", directory + "/")
            script += '''
kcadm() {
  if [[ "$1" == get && "$2" == */federated-identity ]]; then
    printf 'rh-sso,approved-rh-fixture\\n'
  elif [[ "$1" == get ]]; then
    cat "${FIXTURE_DIR}/user.json"
  elif [[ "$1" == update ]]; then
    touch "${FIXTURE_DIR}/updated"
  elif [[ "$1" == create ]]; then
    touch "${FIXTURE_DIR}/created"
  else
    return 99
  fi
}
setup_pilot
'''
            result = subprocess.run(["bash"], input=script, text=True, capture_output=True,
                                    env={**os.environ, "REALM": "internal", "FIXTURE_DIR": directory})
            return result, (work / "updated").exists(), (work / "created").exists()

    def test_existing_approved_link_is_idempotent(self):
        result, updated, created = self.run_setup(APPROVED_RH)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(updated)
        self.assertFalse(created)

    def test_conflicting_origin_rejected_before_mutation(self):
        result, updated, created = self.run_setup("another-rh-subject")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("conflict", result.stderr)
        self.assertFalse(updated or created)


if __name__ == "__main__":
    unittest.main()
