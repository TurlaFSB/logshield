#!/bin/sh
# Apply the repository settings LogShield expects (maintainers only).
#
#   scripts/repo-settings.sh              # settings, security features, topics
#   scripts/repo-settings.sh --protect    # also create/update the main-branch ruleset
#                                         # (after this, main changes go through pull requests)
#
# Needs the GitHub CLI authenticated as a repository admin (`gh auth login`).
# Idempotent: running it twice changes nothing the second time. It sends no
# secrets and reads none; authentication stays inside `gh`.
set -eu

REPO="${REPO:-TurlaFSB/logshield}"
PROTECT=0
case "${1:-}" in
'') ;;
--protect) PROTECT=1 ;;
*)
	echo "usage: $0 [--protect]" >&2
	exit 2
	;;
esac

command -v gh >/dev/null 2>&1 || {
	echo "repo-settings: the GitHub CLI (gh) is required" >&2
	exit 1
}

api() { gh api -H "X-GitHub-Api-Version: 2022-11-28" "$@"; }

echo "repo-settings: $REPO: general settings"
api -X PATCH "repos/$REPO" \
	-f description="Log4Shell virtual-patch reverse proxy: a compensating control for hosts that cannot be patched" \
	-F has_wiki=false -F has_projects=false \
	-F delete_branch_on_merge=true \
	-F allow_squash_merge=true -F allow_rebase_merge=true -F allow_merge_commit=false \
	-F allow_auto_merge=true >/dev/null

echo "repo-settings: topics"
api -X PUT "repos/$REPO/topics" \
	-f 'names[]=log4shell' -f 'names[]=log4j' -f 'names[]=cve-2021-44228' \
	-f 'names[]=waf' -f 'names[]=reverse-proxy' -f 'names[]=virtual-patching' \
	-f 'names[]=ics' -f 'names[]=golang' -f 'names[]=security' >/dev/null

echo "repo-settings: security features"
api -X PATCH "repos/$REPO" \
	-f 'security_and_analysis[secret_scanning][status]=enabled' \
	-f 'security_and_analysis[secret_scanning_push_protection][status]=enabled' >/dev/null
api -X PUT "repos/$REPO/private-vulnerability-reporting" >/dev/null
api -X PUT "repos/$REPO/vulnerability-alerts" >/dev/null
api -X PUT "repos/$REPO/automated-security-fixes" >/dev/null

echo "repo-settings: workflows get a read-only token by default"
api -X PUT "repos/$REPO/actions/permissions/workflow" \
	-f default_workflow_permissions=read -F can_approve_pull_request_reviews=false >/dev/null

if [ "$PROTECT" -eq 1 ]; then
	echo "repo-settings: main-branch ruleset"
	body=$(
		cat <<'JSON'
{
  "name": "protect-main",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "bypass_actors": [
    { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "pull_request" }
  ],
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "required_linear_history" },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": false,
        "require_last_push_approval": false,
        "required_review_thread_resolution": true
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "required_status_checks": [
          { "context": "Lint" },
          { "context": "Lab scripts (shellcheck, ruff)" },
          { "context": "Modules are tidy and verified" },
          { "context": "govulncheck" },
          { "context": "Proxy in front of real backends" },
          { "context": "Latency budget smoke test" }
        ]
      }
    }
  ]
}
JSON
	)
	id=$(api "repos/$REPO/rulesets" --jq '.[] | select(.name=="protect-main") | .id' || true)
	if [ -n "$id" ]; then
		printf '%s' "$body" | api -X PUT "repos/$REPO/rulesets/$id" --input - >/dev/null
	else
		printf '%s' "$body" | api -X POST "repos/$REPO/rulesets" --input - >/dev/null
	fi
fi

echo "repo-settings: done"
