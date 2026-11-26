#!/usr/bin/env bash
# Secrets out of .env files: a CI job fetches its DB password at runtime.

source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"
init_demo ci-secrets

title "Secrets out of .env files"

step "An operator stores the database credentials once"
rpc kms_keystore.Put "$(jq -nc '{Name:"examples/ci/db", Secret:{host:"db.internal:5432", user:"migrator", password:"s3cr3t-rotate-me"}}')" >/dev/null
ok "stored as examples/ci/db"

step "The repo has no .env file and no password"
mkdir -p repo
cat >repo/deploy.sh <<'SH'
#!/usr/bin/env bash
# CI job: only ORBITPORT_PAT is set, as a CI secret
echo "connecting to $DB_HOST as $DB_USER (password ${#DB_PASSWORD} chars)"
SH
show <repo/deploy.sh
if grep -rqi 's3cr3t' repo; then bad "password found in repo"; else ok "grep finds no password in the repo"; fi

step "The CI job fetches the secret at runtime and runs"
secret=$(rpc kms_keystore.Get '{"Name":"examples/ci/db"}' | jq -c '.Secret')
DB_HOST=$(echo "$secret" | jq -r '.host') DB_USER=$(echo "$secret" | jq -r '.user') \
  DB_PASSWORD=$(echo "$secret" | jq -r '.password') bash repo/deploy.sh | show
ok "job ran with credentials fetched at runtime, nothing written to disk"
note "Rotating the password is one Put. Every job picks it up on its next run."

done_banner
