#!/usr/bin/env bash
# Secrets per environment: the same names under dev/ and prod/ prefixes.

source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"
init_demo secrets-per-environment

title "Secrets per environment"

step "Store the same secrets for dev and prod"
for env in dev prod; do
  rpc kms_keystore.Put "$(jq -nc --arg n "examples/$env/db" --arg e "$env" '{Name:$n, Secret:{url:"postgres://app@db-\($e).internal/app", password:"\($e)-db-password"}}')" >/dev/null
  rpc kms_keystore.Put "$(jq -nc --arg n "examples/$env/payments" --arg e "$env" '{Name:$n, Secret:{api_key:"pk_\($e)_51Hx..."}}')" >/dev/null
done
ok "examples/dev/{db,payments} and examples/prod/{db,payments}"

step "List each environment"
for env in dev prod; do
  info "$env:"
  rpc kms_keystore.List "$(jq -nc --arg p "examples/$env" '{Prefix:$p}')" | jq -r '.Names[]' | show
done

step "A deploy reads only its own environment"
for env in dev prod; do
  url=$(rpc kms_keystore.Get "$(jq -nc --arg n "examples/$env/db" '{Name:$n}')" | jq -r '.Secret.url')
  ok "ENV=$env  DATABASE_URL=$url"
done
note "Same code, same secret names; the prefix picks the environment."

done_banner
