"""Internal Agent A: fixed C-then-B interaction using the approved RH user."""
import os
from pathlib import Path
import time

import jwt

from server import AgentHandler
from security import (EXTERNAL_SUB, INTERNAL_SUB, RH_ISSUER, call_agent, identity,
                      request, summary, valid_provenance, verify)


class AgentAHandler(AgentHandler):
    def authenticate(self, bearer, request_id):
        # This entry endpoint accepts an assertion for the existing RH JWT grant,
        # not an Internal/External access token or identity from message metadata.
        try:
            rh = verify(bearer, RH_ISSUER, "cloud-services")
            if rh.get("typ") != "ID" or time.time() - rh["iat"] > 900:
                raise ValueError("Fresh ID assertion required")
        except (jwt.PyJWTError, ValueError):
            return self.reject(401, "rh_assertion_invalid", "rh_assertion_validation", request_id)
        self.stage_passed("rh_assertion_validation", request_id)
        return rh

    def execute(self, bearer, rh, nonce, request_id):
        internal = os.environ["INTERNAL_ISSUER"]
        external = os.environ["EXTERNAL_ISSUER"]
        # Only OAuth client credentials are mounted. No Admin API or Kubernetes credentials.
        secrets = {side: Path(f"/clients/{side}-secret").read_text() for side in ("internal", "external")}

        def oauth(side, form, stage):
            self.record("stage", stage=stage, status="started", requestId=request_id)
            form.update(client_id="agent-a-" + side, client_secret=secrets[side])
            target = internal if side == "internal" else external
            status, response = request(target + "/protocol/openid-connect/token", method="POST",
                                       form=form, allowed=(200, 400, 401, 403))
            if status != 200 or "refresh_token" in response:
                self.record("stage", stage=stage, status="failed", requestId=request_id,
                            httpStatus=status, oauthError=response.get("error", "unexpected_refresh_token"))
                raise PermissionError("OAuth grant rejected or refresh token returned")
            self.stage_passed(stage, request_id)
            return response["access_token"]

        def exchange(t1, audience, scope, stage):
            # RFC 8693 §2.1: separately authenticated, form-encoded token exchange.
            return oauth("internal", {
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": t1, "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "audience": audience, "scope": scope}, stage)

        def validate(token, issuer, audience, subject, client, *, single=True):
            claims = verify(token, issuer, audience, single=single)
            if (claims["sub"] != subject or claims.get("azp") != client or claims.get("typ") != "Bearer"
                    or not valid_provenance(claims) or claims["origin_sub"] != rh["sub"]):
                raise ValueError("Approved user, client or signed provenance mismatch")
            return claims

        t1 = oauth("internal", {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                   "assertion": bearer, "scope": "partner.invoke c.invoke"}, "internal_rh_grant")
        c1 = validate(t1, internal, external, INTERNAL_SUB, "agent-a-internal", single=False)
        if not {"partner.invoke", "c.invoke"} <= set(c1.get("scope", "").split()):
            raise ValueError("Internal authorization context lacks required scopes")
        self.stage_passed("approved_internal_context", request_id)
        tc = exchange(t1, "agent-c", "c.invoke", "internal_c_exchange")
        cc = validate(tc, internal, "agent-c", INTERNAL_SUB, "agent-a-internal")
        self.record("stage", stage="call_agent_c", status="started", requestId=request_id)
        cs, cr, ce = call_agent("agent-c", os.environ["AGENT_C_URL"], internal, tc,
                               metadata={"parentRequestId": request_id})
        if cs != 200:
            raise ValueError("Agent C rejected invocation")
        self.stage_passed("call_agent_c", request_id)
        t2 = exchange(t1, external, "partner.invoke", "internal_partner_exchange")
        c2 = validate(t2, internal, external, INTERNAL_SUB, "agent-a-internal")
        t3 = oauth("external", {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                   "assertion": t2, "scope": "partner.invoke"}, "external_jwt_grant")
        c3 = validate(t3, external, "agent-b", EXTERNAL_SUB, "agent-a-external")
        self.record("stage", stage="call_agent_b", status="started", requestId=request_id)
        bs, br, be = call_agent("agent-b", os.environ["AGENT_B_URL"], external, t3,
                               metadata={"parentRequestId": request_id})
        if bs != 200:
            raise ValueError("Agent B rejected invocation")
        self.stage_passed("call_agent_b", request_id)
        tokens = {name: summary(raw, claims) for name, raw, claims in
                  [("t1", t1, c1), ("tc", tc, cc), ("t2", t2, c2), ("t3", t3, c3)]}
        self.record("execution", stage="cross_idp_complete", requestId=request_id,
                    downstreamRequests={"agent-c": ce["request"]["id"], "agent-b": be["request"]["id"]},
                    tokens=tokens, rh=summary(bearer, rh), **identity(c1))
        return {"nonce": nonce, "agent": "agent-a", "identity": identity(c1), "tokens": tokens,
                "rh": summary(bearer, rh),
                "downstream": {"agent-c": {"response": cr, **ce}, "agent-b": {"response": br, **be}}}
