"""Shared HTTPS and pinned-issuer JWT validation for the PoC agents."""
import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import OrderedDict
import jwt
from a2a import types
from google.protobuf.json_format import MessageToDict, ParseDict

KEY_CACHE = OrderedDict()
INTERNAL_SUB = "11111111-1111-4111-8111-111111111111"
EXTERNAL_SUB = "22222222-2222-4222-8222-222222222222"
RH_ISSUER = "https://sso.stage.redhat.com/auth/realms/redhat-external"


def identity(claims):
    """Report distinct identities without disclosing the RH subject."""
    return {"user": claims["sub"], "authorizedClient": claims["azp"],
            "issuer": claims["iss"], "originIssuer": claims.get("origin_issuer"),
            "originSubjectSha256": hashlib.sha256(claims.get("origin_sub", "").encode()).hexdigest(),
            "internalUser": claims.get("internal_sub"),
            "provenanceVersion": claims.get("provenance_version"),
            "provenance": "trusted-transitive"}


def valid_provenance(claims):
    # Values are attested by the pinned Keycloak issuer, not by a runner-fed record.
    return (claims.get("origin_issuer") == RH_ISSUER
            and isinstance(claims.get("origin_sub"), str) and bool(claims["origin_sub"].strip())
            and claims.get("internal_sub") == INTERNAL_SUB
            and claims.get("provenance_version") == "1")


def summary(token, claims):
    return {"sha256": hashlib.sha256(token.encode()).hexdigest(),
            "jti": claims["jti"], "issuer": claims["iss"],
            "subjectSha256": hashlib.sha256(claims["sub"].encode()).hexdigest(),
            "audience": claims.get("aud"), "expires": claims["exp"], "issuedAt": claims["iat"],
            "authenticationTime": claims.get("auth_time"),
            "azp": claims.get("azp"), "scope": claims.get("scope", ""),
            "permissions": claims.get("permissions", []), "signatureVerified": True}

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
HTTP = urllib.request.build_opener(NoRedirect)
MAX_RESPONSE = 2 * 1024 * 1024

def request(url, method="GET", payload=None, token=None, form=None,
            allowed=(200, 201, 204), extra_headers=None, timeout=30):
    if not url.startswith("https://"):
        raise RuntimeError("HTTPS required")
    headers = {"Accept": "application/json"}
    headers.update(extra_headers or {})
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode()
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        data = urllib.parse.urlencode(form).encode()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with HTTP.open(req, timeout=timeout) as response:
            status, raw = response.status, response.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as error:
        with error:
            status, raw = error.code, error.read(MAX_RESPONSE + 1)
    if len(raw) > MAX_RESPONSE:
        raise RuntimeError("Oversized server response")
    if status not in allowed:
        # Never print upstream bodies, which can include submitted credentials or personal data.
        raise RuntimeError(f"HTTPS {method} {urllib.parse.urlsplit(url).path}: HTTP {status}")
    return status, json.loads(raw) if raw else None

def access_token(base, realm, client, secret):
    return request(f"{base}/realms/{realm}/protocol/openid-connect/token", method="POST", form={
        "grant_type": "client_credentials", "client_id": client, "client_secret": secret})[1]["access_token"]

def protocol_json(value, model):
    return MessageToDict(ParseDict(value, model()))


def call_agent(agent, url, expected_issuer, token, *, operation="identity-check", metadata=None, timeout=30):
    """Discover a pinned A2A peer and validate its SendMessage reply."""
    status, raw_card = request(url + "/.well-known/agent-card.json")
    card = ParseDict(raw_card, types.AgentCard())
    if (card.name != agent or len(card.supported_interfaces) != 1
            or card.supported_interfaces[0].url != url + "/a2a"
            or card.supported_interfaces[0].protocol_version != "1.0"
            or card.supported_interfaces[0].protocol_binding != "JSONRPC"
            or card.security_schemes["oidc"].open_id_connect_security_scheme.open_id_connect_url !=
            expected_issuer + "/.well-known/openid-configuration"):
        raise ValueError("Agent Card differs from the approved endpoint/issuer/interface")
    nonce = str(uuid.uuid4())
    params = {"message": {"messageId": str(uuid.uuid4()), "role": "ROLE_USER",
              "parts": [{"text": json.dumps({"operation": operation, "nonce": nonce})}]}}
    if metadata:
        params["message"]["metadata"] = metadata
    envelope = {"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": "SendMessage",
                "params": protocol_json(params, types.SendMessageRequest)}
    # RFC 6750 §2.1: downstream access tokens use the Authorization header.
    status, response = request(url + "/a2a", method="POST", payload=envelope, token=token,
        extra_headers={"A2A-Version": "1.0", "X-Request-ID": envelope["id"]},
        allowed=(200, 400, 401, 403, 502), timeout=timeout)
    if status == 200:
        if response.get("jsonrpc") != "2.0" or response.get("id") != envelope["id"]:
            raise ValueError("JSON-RPC response ID mismatch")
        result = ParseDict(response["result"], types.SendMessageResponse())
        output = json.loads(result.message.parts[0].text)
        if result.message.role != types.Role.ROLE_AGENT or output["nonce"] != nonce or output["agent"] != agent:
            raise ValueError("Invalid A2A result or nonce")
    return status, response, {"request": envelope, "nonce": nonce, "card": raw_card}

def signing_keys(expected_issuer, *, refresh=False):
    cached = KEY_CACHE.get(expected_issuer)
    if not refresh and cached and cached[0] > time.monotonic():
        return cached[1]
    metadata = request(expected_issuer + "/.well-known/openid-configuration")[1]
    if metadata["issuer"] != expected_issuer:
        raise ValueError("Discovery issuer mismatch")
    jwks_uri = expected_issuer + "/protocol/openid-connect/certs"
    if metadata["jwks_uri"] != jwks_uri:
        raise ValueError("Discovery JWKS location mismatch")
    keys = request(jwks_uri)[1]["keys"]
    KEY_CACHE[expected_issuer] = (time.monotonic() + 30, keys)
    KEY_CACHE.move_to_end(expected_issuer)
    while len(KEY_CACHE) > 8:
        KEY_CACHE.popitem(last=False)
    return keys

def verify(token, expected_issuer, audience, *, single=True):
    # RFC 7523 §3: issuer/audience, expiration and signature validation.
    # The approved issuer selects metadata and keys; token URLs never select trust.
    header = jwt.get_unverified_header(token)
    if header.get("alg") != "RS256" or not header.get("kid"):
        raise ValueError("Unapproved algorithm or missing key ID")
    keys = signing_keys(expected_issuer)
    if not any(key.get("kid") == header["kid"] for key in keys):
        keys = signing_keys(expected_issuer, refresh=True)
    matches = [k for k in keys if k.get("kid") == header["kid"] and k.get("kty") == "RSA"
               and k.get("use", "sig") == "sig" and k.get("alg", "RS256") == "RS256"]
    if len(matches) != 1:
        raise ValueError("Unknown or ambiguous signing key")
    key = jwt.PyJWK.from_dict(matches[0], algorithm="RS256")
    claims = jwt.decode(token, key.key, algorithms=["RS256"], issuer=expected_issuer,
                        audience=audience, options={"require": ["iss", "sub", "aud", "exp", "iat", "jti"]})
    aud = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
    if single and aud != [audience]:
        raise ValueError("Expected a single exact audience")
    return claims
