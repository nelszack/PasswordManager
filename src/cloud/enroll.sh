set -eu
root="$HOME/.local/share/pm-sync"
[ -f "$root/deployment.json" ] || { echo 'Run sync setup on the server first.' >&2; exit 1; }
"$HOME/.local/bin/pm-sync" --data "$root" --enroll-stdio "$1"
