#!/usr/bin/env bash
# strfry writePolicy plugin wrapper: sets config via env, then execs the binary.
# Point relay.writePolicy.plugin at this script.
export RL_WINDOW_SECONDS=180
export RL_MAX_EVENTS=100
export RL_MODE=reject
export RL_BAN_ON_EXCEED=true
export RL_BAN_LIST_FILE=/Volumes/1TB/strfry/strfry-db/banned-pubkeys.txt
export RL_EXCLUDE_KINDS=7
export RL_EXEMPT_EPHEMERAL=true
export RL_EXEMPT_REPLACEABLE=true
export RL_EXEMPT_ADDRESSABLE=false
exec "$(dirname "$0")/../target/release/strfry-ratelimit"
