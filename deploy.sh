#!/bin/bash
# Create or recreate the complete two-instance Multi-IdP lab.
set -euo pipefail

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly NAMESPACES=(multi-idp-internal multi-idp-external)
RESET=false

if [[ "${1:-}" == "--reset" ]]; then
  RESET=true
elif [[ $# -gt 0 ]]; then
  echo "Usage: $0 [--reset]" >&2
  exit 2
fi

if [[ ! -s "${ROOT}/.private/approved-rh-subject" ]]; then
  echo 'Set .private/approved-rh-subject to the explicitly approved stage RH' \
    'subject before deploying. Never derive approval during a runtime test.' >&2
  exit 1
fi
chmod 600 "${ROOT}/.private/approved-rh-subject"

for namespace in "${NAMESPACES[@]}"; do
  if ! oc get namespace "${namespace}" >/dev/null 2>&1; then
    oc create namespace "${namespace}"
  fi

  if ! oc get secret database -n "${namespace}" >/dev/null 2>&1; then
    oc create secret generic database -n "${namespace}" \
      --from-file=username=<(printf keycloak) \
      --from-file=password=<(openssl rand -hex 32 | tr -d '\n') \
      --dry-run=client -o yaml | oc apply -f -
  fi

  if ! oc get secret credentials -n "${namespace}" >/dev/null 2>&1; then
    oc create secret generic credentials -n "${namespace}" \
      --from-file=provisioner-secret=<(openssl rand -hex 32 | tr -d '\n') \
      --from-file=agent-secret=<(openssl rand -hex 32 | tr -d '\n') \
      --from-file=other-agent-secret=<(openssl rand -hex 32 | tr -d '\n') \
      --dry-run=client -o yaml | oc apply -f -
  fi

  if ! oc get secret console-admin -n "${namespace}" >/dev/null 2>&1; then
    oc create secret generic console-admin -n "${namespace}" \
      --from-file=password=<(openssl rand -hex 32 | tr -d '\n') \
      --dry-run=client -o yaml | oc apply -f -
  fi
  oc create secret generic approved-pilot -n "${namespace}" \
    --from-file=origin-sub="${ROOT}/.private/approved-rh-subject" \
    --dry-run=client -o yaml | oc apply -f -
done

# Supply only A's OAuth client secrets.
oc create secret generic agent-a-clients -n multi-idp-internal \
  --from-file=internal-secret=<(oc get secret credentials \
    -n multi-idp-internal -o go-template='{{index .data "agent-secret"}}' \
    | base64 -d) \
  --from-file=external-secret=<(oc get secret credentials \
    -n multi-idp-external -o go-template='{{index .data "agent-secret"}}' \
    | base64 -d) --dry-run=client -o yaml | oc apply -f -

if [[ "${RESET}" == true ]]; then
  if [[ -f "${ROOT}/evidence/installation.json" ]]; then
    cp "${ROOT}/evidence/installation.json" \
      "${ROOT}/evidence/installation-before-reset.json"
  fi
  for namespace in "${NAMESPACES[@]}"; do
    if oc get deployment/rhbk -n "${namespace}" >/dev/null 2>&1; then
      oc scale deployment/rhbk --replicas=0 -n "${namespace}"
    fi
    if oc get statefulset/database -n "${namespace}" >/dev/null 2>&1; then
      oc scale statefulset/database --replicas=0 -n "${namespace}"
    fi
    oc delete pod -l app=rhbk -n "${namespace}" \
      --ignore-not-found --wait=true
    oc delete pod -l app=database -n "${namespace}" \
      --ignore-not-found --wait=true
    oc delete job -l app=bootstrap -n "${namespace}" --ignore-not-found
    oc delete pvc data-database-0 -n "${namespace}" \
      --ignore-not-found --wait=true
  done
fi

# Re-run bootstrap to validate/apply approved pilot setup.
for namespace in "${NAMESPACES[@]}"; do
  oc delete job realm-bootstrap-v4 -n "${namespace}" --ignore-not-found
done
oc apply -k "${ROOT}"
for namespace in "${NAMESPACES[@]}"; do
  oc wait --for=condition=complete job/realm-bootstrap-v4 \
    -n "${namespace}" --timeout=600s
done
for agent in agent-a agent-c; do
  oc rollout restart "deployment/${agent}" -n multi-idp-internal
  oc rollout status "deployment/${agent}" -n multi-idp-internal --timeout=300s
done
oc rollout restart deployment/agent-b -n multi-idp-external
oc rollout status deployment/agent-b -n multi-idp-external --timeout=300s

echo "Both Keycloak instances are ready. Console passwords are in the" \
  "console-admin Secrets in their respective namespaces."
