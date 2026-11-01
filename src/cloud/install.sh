# Arguments are supplied by the client as individually quoted shell words.
set -eu
umask 077
nonce=$1
listen_port=$2
https_port=$3
server_url=$4
new_route=$5
update_only=$6
bin="$HOME/.local/bin/pm-sync"
stage="$HOME/.local/bin/.pm-sync-upload-$nonce"
root="$HOME/.local/share/pm-sync"
unit="$HOME/.config/systemd/user/pm-sync.service"
lock="$root/deploy.lock"
mkdir -p "$root" "$(dirname "$unit")"
chmod 700 "$root"
mkdir "$lock" || { echo 'Another sync installation is running.' >&2; exit 1; }
changed=0
route_changed=0
had_binary=0
had_unit=0
had_manifest=0
was_active=0
was_enabled=0
systemctl --user is-active --quiet pm-sync.service && was_active=1
systemctl --user is-enabled --quiet pm-sync.service && was_enabled=1
cleanup() {
  result=$?
  trap - EXIT HUP INT TERM
  if [ "$result" != 0 ] && [ "$changed" = 1 ]; then
    if [ "$route_changed" = 1 ]; then tailscale serve --https="$https_port" off >&2 || true; fi
    if [ "$had_binary" = 1 ]; then mv "$bin.previous" "$bin"; else [ ! -f "$bin" ] || rm "$bin"; fi
    if [ "$had_unit" = 1 ]; then mv "$unit.previous" "$unit"; else [ ! -f "$unit" ] || rm "$unit"; fi
    if [ "$had_manifest" = 1 ]; then mv "$root/deployment.previous.json" "$root/deployment.json"; else [ ! -f "$root/deployment.json" ] || rm "$root/deployment.json"; fi
    systemctl --user daemon-reload >&2 || true
    if [ "$was_active" = 1 ]; then systemctl --user restart pm-sync.service >&2 || true; else systemctl --user stop pm-sync.service >&2 || true; fi
    if [ "$was_enabled" = 0 ]; then systemctl --user disable pm-sync.service >&2 || true; fi
    echo 'Installation failed. Previous service files were restored; vault data was preserved.' >&2
  fi
  for file in "$stage" "$unit.new-$nonce" "$root/deployment.new-$nonce.json"; do [ ! -f "$file" ] || rm "$file"; done
  rmdir "$lock" || true
  exit "$result"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
fragment=$(systemctl --user show pm-sync.service --property=FragmentPath --value 2>/dev/null || true)
if [ -n "$fragment" ] && [ "$fragment" != "$unit" ]; then
  echo 'A pm-sync service is supplied by another installation. Refusing to override it.' >&2
  exit 1
fi
if [ -f "$unit" ] && ! grep -q '^# Managed by Password Manager sync setup v1$' "$unit"; then
  echo 'An unmanaged pm-sync.service already exists. Refusing to overwrite it.' >&2
  exit 1
fi
if [ "$update_only" = 1 ] && { [ ! -f "$bin" ] || [ ! -f "$root/deployment.json" ]; }; then
  echo 'No managed installation exists. Run sync setup first.' >&2
  exit 1
fi
[ -f "$stage" ] || { echo 'Uploaded server binary is missing.' >&2; exit 1; }
"$stage" --version >/dev/null
if [ -f "$bin" ]; then cp -p "$bin" "$bin.previous"; had_binary=1; fi
if [ -f "$unit" ]; then cp -p "$unit" "$unit.previous"; had_unit=1; fi
if [ -f "$root/deployment.json" ]; then cp -p "$root/deployment.json" "$root/deployment.previous.json"; had_manifest=1; fi
# Preserve customized storage limits and service settings on managed updates.
if [ "$had_unit" = 1 ]; then
  cp -p "$unit" "$unit.new-$nonce"
else
@WRITE_UNIT@
fi
printf '{"schema":1,"listen_port":%s,"https_port":%s,"server_url":"%s"}\n' "$listen_port" "$https_port" "$server_url" > "$root/deployment.new-$nonce.json"
changed=1
mv "$stage" "$bin"
mv "$unit.new-$nonce" "$unit"
systemctl --user daemon-reload >&2
systemctl --user enable pm-sync.service >&2
systemctl --user restart pm-sync.service >&2
healthy=0
for attempt in 1 2 3 4 5; do
  if "$bin" --health-check "http://127.0.0.1:$listen_port" >/dev/null 2>&1; then healthy=1; break; fi
  sleep 1
done
[ "$healthy" = 1 ] || { echo 'The new sync service failed its health check.' >&2; exit 1; }
if [ "$new_route" = 1 ]; then
  route_changed=1
  tailscale serve --bg --yes --https="$https_port" "http://127.0.0.1:$listen_port" >&2
fi
mv "$root/deployment.new-$nonce.json" "$root/deployment.json"
printf '%s\n' "$server_url"
