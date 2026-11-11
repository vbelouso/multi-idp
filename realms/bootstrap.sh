#!/bin/bash
# Complete the native realm import using the bundled Keycloak Admin CLI.
set -euo pipefail
umask 077
current_stage=script_start

# Log a structured stage record without emitting credential values.
log() {
  printf '%s level=INFO component=realm-bootstrap realm=%s %s\n' \
    "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "${REALM:-unknown}" "$*"
}

begin_stage() {
  current_stage="$1"
  log "stage=${current_stage} status=started"
}

complete_stage() {
  log "stage=${current_stage} status=completed"
}

# Report the last active stage when an unhandled command fails.
on_error() {
  local status=$?
  trap - ERR
  log "stage=${current_stage} status=failed exit_code=${status}"
  exit "${status}"
}

trap on_error ERR

# Keep the credential cache in the memory-backed work directory.
kcadm() {
  /opt/keycloak/bin/kcadm.sh "$@" --config /work/admin.config
}

# Establish the explicitly approved pilot relationship before runtime.
setup_pilot() {
  local subject alias upstream current provider linked=false key value
  local attribute_name expected_attribute
  local origin_issuer=https://sso.stage.redhat.com/auth/realms/redhat-external
  local internal_sub=11111111-1111-4111-8111-111111111111
  local external_sub=22222222-2222-4222-8222-222222222222
  local approved_sub
  approved_sub="$(</approval/origin-sub)"
  if [[ ! "${approved_sub}" =~ ^[a-zA-Z0-9._:@-]+$ ]]; then
    echo 'Missing or invalid explicitly approved RH subject.' >&2
    return 1
  fi
  subject="${internal_sub}"
  alias=rh-sso
  upstream="${approved_sub}"
  if [[ "${REALM}" == partner ]]; then
    subject="${external_sub}"
    alias=internal
    upstream="${internal_sub}"
  fi
  begin_stage approved_pilot_preflight
  current="$(kcadm get "users/${subject}" -r "${REALM}" \
    --fields 'attributes(*)')"
  current="${current//[[:space:]]/}"
  # An existing conflicting protected value is never silently overwritten.
  for key in origin_issuer origin_sub internal_sub provenance_version; do
    case "${key}" in
      origin_issuer) value="${origin_issuer}" ;;
      origin_sub) value="${approved_sub}" ;;
      internal_sub) value="${internal_sub}" ;;
      provenance_version) value=1 ;;
    esac
    attribute_name="\"${key}\":"
    expected_attribute="${attribute_name}[\"${value}\"]"
    if [[ "${current}" == *"${attribute_name}"* &&
          "${current}" != *"${expected_attribute}"* ]]; then
      echo 'Protected pilot attributes conflict with explicit approval.' >&2
      return 1
    fi
  done
  kcadm get "users/${subject}/federated-identity" -r "${REALM}" \
    --fields identityProvider,userId --format csv --noquotes >/work/links.csv
  while IFS=, read -r provider current; do
    if [[ "${provider}" == "${alias}" ]]; then
      if [[ "${current}" != "${upstream}" ]]; then
        echo 'Existing pilot link conflicts with explicit approval.' >&2
        return 1
      fi
      linked=true
    fi
  done </work/links.csv
  complete_stage
  begin_stage approved_pilot_link
  if [[ "${linked}" == false ]]; then
    kcadm create "users/${subject}/federated-identity/${alias}" \
      -r "${REALM}" -s "identityProvider=${alias}" \
      -s "userId=${upstream}" -s userName=approved-pilot >/work/link.log 2>&1
  fi
  complete_stage
  begin_stage approved_pilot_attributes
  kcadm update "users/${subject}" -r "${REALM}" \
    -s "attributes.origin_issuer=[\"${origin_issuer}\"]" \
    -s "attributes.origin_sub=[\"${approved_sub}\"]" \
    -s "attributes.internal_sub=[\"${internal_sub}\"]" \
    -s 'attributes.provenance_version=["1"]'
  complete_stage
}

main() {
  local current attempt scope_id scope_name client_id login_ok=false
  local scope_linked=false

  log "stage=bootstrap status=started revision=${REVISION}"

  # All credentials stay in Secret-backed environment variables and /work.
  begin_stage service_account_login
  if KC_CLI_CLIENT_SECRET="${PROVISIONER_SECRET}" kcadm \
    config credentials --server "${BASE_URL}" --realm "${REALM}" \
    --client realm-provisioner >/work/login.log 2>&1; then
    complete_stage
    begin_stage existing_realm_check
    if current="$(kcadm get "realms/${REALM}" --fields 'attributes(*)' \
      2>/work/realm-read.log)"; then
      if [[ "${current}" == *'"multi-idp-poc"'* &&
            "${current}" == *"${REVISION}"* &&
            "${current}" == *'"complete"'* ]]; then
        complete_stage
        setup_pilot
        log 'stage=bootstrap status=already_complete verified=realm_provisioner'
        exit 0
      fi
      if [[ "${current}" != *'"multi-idp-poc"'* ||
            "${current}" != *"${REVISION}"* ]]; then
        log 'stage=existing_realm_check status=failed' \
          'reason=ownership_or_revision_mismatch'
        echo 'Realm ownership/revision mismatch; reset the lab.' >&2
        exit 1
      fi
      complete_stage
    else
      log 'stage=existing_realm_check status=deferred' \
        'reason=service_account_roles_pending'
    fi
    # A newly imported service account can log in before it has admin roles.
  else
    log 'stage=service_account_login status=unavailable action=use_master_admin'
  fi

  begin_stage master_admin_login
  for ((attempt = 0; attempt < 60; attempt++)); do
    if KC_CLI_PASSWORD="${INITIAL_ADMIN_PASSWORD}" kcadm \
      config credentials --server "${BASE_URL}" --realm master \
      --user console-admin >/work/login.log 2>&1; then
      login_ok=true
      log "stage=master_admin_login status=authenticated" \
        "attempts=$((attempt + 1))"
      break
    fi
    if (( attempt == 0 || (attempt + 1) % 6 == 0 )); then
      log "stage=master_admin_login status=retry" \
        "attempt=$((attempt + 1)) max_attempts=60"
    fi
    sleep 5
  done
  if [[ "${login_ok}" != true ]]; then
    log 'stage=master_admin_login status=failed attempts=60'
    echo 'Unable to authenticate the bootstrap administrator.' >&2
    exit 1
  fi

  begin_stage realm_revision_check
  current="$(kcadm get "realms/${REALM}" --fields 'attributes(*)')"
  if [[ "${current}" != *'"multi-idp-poc"'* ||
        "${current}" != *"${REVISION}"* ]]; then
    log 'stage=realm_revision_check status=failed' \
      'reason=ownership_or_revision_mismatch'
    echo 'Realm ownership/revision mismatch; reset the lab.' >&2
    exit 1
  fi
  complete_stage

  begin_stage user_profile_update
  kcadm update users/profile -r "${REALM}" -f /config/profile.json
  complete_stage

  begin_stage provisioner_role_assignment
  kcadm add-roles -r "${REALM}" \
    --uusername service-account-realm-provisioner \
    --cclientid realm-management \
    --rolename manage-realm --rolename manage-clients --rolename manage-users \
    --rolename view-events --rolename view-realm --rolename query-users \
    --rolename query-clients --rolename view-identity-providers \
    --rolename manage-identity-providers
  complete_stage

  begin_stage provisioner_client_lookup
  client_id="$(kcadm get clients -r "${REALM}" \
    -q clientId=realm-provisioner --fields id --format csv --noquotes)"
  complete_stage

  begin_stage admin_scope_lookup
  kcadm get client-scopes -r "${REALM}" \
    --fields id,name --format csv --noquotes >/work/scopes.csv
  complete_stage

  begin_stage admin_scope_link
  while IFS=, read -r scope_id scope_name; do
    if [[ "${scope_name}" == kc-admin-api ]]; then
      kcadm update \
        "clients/${client_id}/default-client-scopes/${scope_id}" -r "${REALM}"
      scope_linked=true
    fi
  done </work/scopes.csv
  if [[ "${scope_linked}" == true ]]; then
    complete_stage
  else
    log 'stage=admin_scope_link status=skipped reason=kc-admin-api_not_found'
  fi

  begin_stage scoped_service_account_verification
  KC_CLI_CLIENT_SECRET="${PROVISIONER_SECRET}" \
    /opt/keycloak/bin/kcadm.sh config credentials \
    --server "${BASE_URL}" --realm "${REALM}" \
    --client realm-provisioner --config /work/scoped.config \
    >/work/login.log 2>&1
  /opt/keycloak/bin/kcadm.sh get "realms/${REALM}" \
    --config /work/scoped.config --fields realm >/dev/null
  complete_stage

  begin_stage bootstrap_marker_update
  /opt/keycloak/bin/kcadm.sh update "realms/${REALM}" \
    --config /work/scoped.config -s 'attributes.multi-idp-bootstrap=complete'
  complete_stage
  setup_pilot
  log 'stage=bootstrap status=completed' \
    'master_admin_login=verified scoped_service_account=verified'
}

main "$@"
