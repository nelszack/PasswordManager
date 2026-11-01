set -eu
[ "$(uname -s)" = Linux ] || { echo 'The sync host must run Linux.' >&2; exit 1; }
command -v systemctl >/dev/null
command -v tailscale >/dev/null
command -v ss >/dev/null
systemctl --user show-environment >/dev/null
case "$1" in
  machine) uname -m ;;
  tailscale) tailscale status --json ;;
  serve) tailscale serve status --json ;;
  ports) ss -ltnH ;;
  deployment)
    file="$HOME/.local/share/pm-sync/deployment.json"
    if [ -f "$file" ]; then cat "$file"; else printf '{}\n'; fi ;;
  *) exit 2 ;;
esac
