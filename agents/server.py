"""Deterministic A2A 1.0 resource agent with issuer and operation authorization."""

import argparse
import datetime
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import ssl
import sys
import time
import uuid

from a2a import types
from google.protobuf.json_format import ParseDict, ParseError
import jwt

from security import INTERNAL_SUB, EXTERNAL_SUB, identity, protocol_json, valid_provenance, verify


def emit_log(agent, event, **fields):
    entry = {"utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
             "component": "agent", "agent": agent, "event": event, **fields}
    print(json.dumps(entry), flush=True)


class AgentHTTPServer(ThreadingHTTPServer):
    def handle_error(self, _request, client_address):
        error = sys.exc_info()[1]
        error_type = type(error).__name__ if error else "UnknownError"
        emit_log(self.agent, "transport_error", stage="http_connection",
                 errorType=error_type, clientAddress=client_address[0])


class AgentHandler(BaseHTTPRequestHandler):
    server_version = "MultiIdpA2A/1.0"

    def log_message(self, *_args):
        pass

    def record(self, event, **fields):
        started = getattr(self, "request_started", None)
        if started is not None:
            fields.setdefault("durationMs", round((time.monotonic() - started) * 1000, 2))
        emit_log(self.server.agent, event, **fields)

    def stage_passed(self, stage, request_id):
        self.record("stage", stage=stage, status="passed", requestId=request_id)

    def send_json(self, status, value, challenge=None):
        raw = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(raw)))
        if challenge:
            self.send_header("WWW-Authenticate", challenge)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/healthz":
            return self.send_json(200, {"status": "ok"})
        if self.path != "/.well-known/agent-card.json":
            self.record("request_rejected", stage="http_routing", reason="not_found",
                        method="GET", path=self.path.split("?", 1)[0],
                        httpStatus=404)
            return self.send_json(404, {"error": "not_found"})
        self.record("agent_card_served", stage="agent_card", status="passed")
        card = {"name": self.server.agent, "description": "Deterministic identity-check agent",
                "version": "0.1.0", "supportedInterfaces": [{"url": self.server.url + "/a2a",
                    "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}], "capabilities": {},
                "defaultInputModes": ["text/plain"], "defaultOutputModes": ["text/plain"],
                "skills": [{"id": "identity-check", "name": "Identity check",
                    "description": "Return an authorized identity summary and request nonce", "tags": ["identity"]}],
                "securitySchemes": {"oidc": {"openIdConnectSecurityScheme": {
                    "openIdConnectUrl": self.server.issuer + "/.well-known/openid-configuration"}}},
                "securityRequirements": [{"schemes": {"oidc": {"list": [self.server.scope]}}}]}
        self.send_json(200, protocol_json(card, types.AgentCard))

    def reject(self, status, reason, stage, request_id=None):
        request_id = request_id or self.headers.get("X-Request-ID")
        self.record("rejected", stage=stage, reason=reason, httpStatus=status,
                    requestId=request_id)
        # RFC 6750 §3.1: invalid_token uses 401; insufficient_scope uses 403.
        error = "invalid_token" if status == 401 else "insufficient_scope"
        return self.send_json(status, {"error": error, "reason": reason},
                              f'Bearer error="{error}"')

    def authenticate(self, bearer, request_id):
        try:
            unverified = jwt.decode(bearer, options={"verify_signature": False})
            if unverified.get("iss") != self.server.issuer:
                return self.reject(401, "unsupported_issuer", "issuer_match", request_id)
            self.stage_passed("issuer_match", request_id)
            # Trust is selected by server configuration, never by token or message metadata.
            claims = verify(bearer, self.server.issuer, self.server.agent)
        except (jwt.PyJWTError, ValueError):
            return self.reject(401, "issuer_signature_audience_or_lifetime",
                               "signature_audience_lifetime_validation", request_id)
        self.stage_passed("signature_audience_lifetime_validation", request_id)
        if claims.get("typ") != "Bearer":
            return self.reject(401, "access_token_required", "access_token_type", request_id)
        self.stage_passed("access_token_type", request_id)
        if claims.get("azp") != self.server.client:
            return self.reject(403, "client_not_approved", "authorized_client", request_id)
        self.stage_passed("authorized_client", request_id)
        if (self.server.scope not in claims.get("scope", "").split() or
                self.server.permission not in claims.get("permissions", [])):
            return self.reject(403, "operation_permission_missing",
                               "scope_and_permission", request_id)
        self.stage_passed("scope_and_permission", request_id)
        expected_sub = EXTERNAL_SUB if self.server.agent == "agent-b" else INTERNAL_SUB
        if claims["sub"] != expected_sub:
            return self.reject(403, "user_not_approved", "approved_subject", request_id)
        self.stage_passed("approved_subject", request_id)
        if self.server.agent == "agent-b":
            if not valid_provenance(claims):
                return self.reject(403, "provenance_inconsistent", "signed_provenance", request_id)
            self.stage_passed("signed_provenance", request_id)
        return claims

    def execute(self, bearer, claims, nonce, request_id):
        return {"nonce": nonce, "agent": self.server.agent, "identity": identity(claims)}

    def do_POST(self):
        if self.path != "/a2a":
            return self.send_json(404, {"error": "not_found"})
        self.request_started = time.monotonic()
        request_id = self.headers.get("X-Request-ID")
        self.record("request_started", stage="bearer_authentication", method="POST",
                    path=self.path, requestId=request_id)
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return self.reject(401, "bearer_required", "bearer_presence", request_id)
        bearer = auth[7:]
        self.stage_passed("bearer_presence", request_id)
        claims = self.authenticate(bearer, request_id)
        if claims is None:
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 65536:
                raise ValueError("invalid_length")
            envelope = json.loads(self.rfile.read(length))
            if not isinstance(envelope, dict):
                raise ValueError("invalid_envelope")
            if envelope.get("jsonrpc") != "2.0" or not isinstance(envelope.get("id"), str):
                raise ValueError("invalid_envelope")
            request_id = envelope["id"]
            if envelope.get("method") != "SendMessage":
                return self.reject(403, "unsupported_operation",
                                   "operation_authorization", request_id)
            if self.headers.get("A2A-Version") != "1.0":
                raise ValueError("unsupported_version")
            params = ParseDict(envelope["params"], types.SendMessageRequest())
            if params.message.role != types.Role.ROLE_USER or not params.message.message_id or len(params.message.parts) != 1:
                raise ValueError("invalid_message")
            operation = json.loads(params.message.parts[0].text)
            if not isinstance(operation, dict):
                raise ValueError("invalid_operation")
            if operation.get("operation") != "identity-check":
                return self.reject(403, "unsupported_operation",
                                   "operation_authorization", request_id)
            if not isinstance(operation.get("nonce"), str):
                raise ValueError("invalid_nonce")
            nonce = str(uuid.UUID(operation["nonce"]))
        except (ValueError, KeyError, ParseError):
            self.record("rejected", stage="a2a_request_validation",
                        reason="invalid_a2a_request", httpStatus=400,
                        requestId=request_id)
            return self.send_json(400, {"error": "invalid_a2a_request"})
        self.stage_passed("a2a_request_validation", request_id)
        self.stage_passed("identity_check_operation", request_id)
        try:
            output = self.execute(bearer, claims, nonce, request_id)
        except PermissionError:
            return self.reject(403, "authorization_server_denied", "oauth_authorization", request_id)
        except Exception as error:
            self.record("failed", stage="downstream_execution", requestId=request_id,
                        errorType=type(error).__name__)
            return self.send_json(502, {"error": "downstream_execution_failed"})
        response = protocol_json({"message": {"messageId": str(uuid.uuid4()), "role": "ROLE_AGENT",
                    "parts": [{"text": json.dumps(output)}]}}, types.SendMessageResponse)
        self.record("processed", stage="complete",
                    requestId=envelope["id"], messageId=params.message.message_id,
                    nonce=nonce, credentialSha256=hashlib.sha256(bearer.encode()).hexdigest(),
                    jti=claims["jti"], **output["identity"])
        self.send_json(200, {"jsonrpc": "2.0", "id": envelope["id"], "result": response})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent", choices=["agent-a", "agent-b", "agent-c"], required=True)
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()
    emit_log(args.agent, "startup", stage="configuration", status="started")
    handler = AgentHandler
    if args.agent == "agent-a":
        from agent_a import AgentAHandler
        handler = AgentAHandler
    server = AgentHTTPServer(("0.0.0.0", args.port), handler)
    server.agent, server.url = args.agent, os.environ["PUBLIC_URL"]
    external = args.agent == "agent-b"
    server.issuer = os.environ["EXPECTED_ISSUER"]
    server.client = "agent-a-external" if external else "agent-a-internal"
    server.scope = "partner.invoke" if external else "c.invoke"
    server.permission = "invoke-b" if external else "invoke-c"
    if args.agent == "agent-a":
        from security import RH_ISSUER
        server.issuer, server.scope = RH_ISSUER, "openid"
        server.permission = "approved_internal_context"
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
    except (OSError, ssl.SSLError) as error:
        emit_log(args.agent, "startup", stage="tls_certificate", status="failed",
                 errorType=type(error).__name__)
        raise
    emit_log(args.agent, "startup", stage="tls_certificate", status="ready")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    emit_log(args.agent, "startup", stage="listener", status="ready",
             url=server.url, issuer=server.issuer, client=server.client,
             requiredScope=server.scope, requiredPermission=server.permission)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        emit_log(args.agent, "shutdown", stage="listener", status="stopped")


if __name__ == "__main__":
    main()
