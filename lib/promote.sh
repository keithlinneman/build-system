# shellcheck shell=bash

init_release_promotion() {
  ## Get assume role for promoting releases
  local assume_role_param
  # could check for component specific role and fallback to app-wide role, all are app-wide for now
  assume_role_param="/app/${APP}/deploy/role/arn"
  DEPLOY_ASSUME_ROLE="$(aws ssm get-parameter --name "${assume_role_param}" --query Parameter.Value --output text)"
  if [[ -z "$DEPLOY_ASSUME_ROLE" ]]; then
    die "failed to resolve required SSM parameters DEPLOY_ASSUME_ROLE"
  fi
  export DEPLOY_ASSUME_ROLE
}

promote_component_release() {
  local component="$1"
  local ssm_release_param="/app/${APP}/${component}/deploy/${RELEASE_TRACK}/release/id"

  ## Get role arn to assume for promoting releases
  local assume_role_param deploy_assume_role
  assume_role_param="/app/${APP}/deploy/role/arn"

  deploy_assume_role="$(aws ssm get-parameter --name "${assume_role_param}" --query Parameter.Value --output text)"
  if [[ -z "$deploy_assume_role" ]]; then
    die "failed to resolve required SSM parameters deploy_assume_role"
  fi

  # assume role in workload account in a subshell
  (
    log "==> (promote) assuming role=${deploy_assume_role} for component=${component} promotion"
    local credentials
    credentials="$( aws sts assume-role --role-arn "${deploy_assume_role}" --role-session-name "promote-${component}-${RELEASE_ID:0:8}" )"
    export AWS_ACCESS_KEY_ID
    export AWS_SECRET_ACCESS_KEY
    export AWS_SESSION_TOKEN
    AWS_ACCESS_KEY_ID=$(echo "$credentials" | jq -r '.Credentials.AccessKeyId')
    AWS_SECRET_ACCESS_KEY=$(echo "$credentials" | jq -r '.Credentials.SecretAccessKey')
    AWS_SESSION_TOKEN=$(echo "$credentials" | jq -r '.Credentials.SessionToken')

    log "==> (promote) setting release id=${RELEASE_ID} for component=${component} via ssm param=${ssm_release_param}"
    aws ssm put-parameter --name "${ssm_release_param}" --type String --value "${RELEASE_ID}" --overwrite
  )

}