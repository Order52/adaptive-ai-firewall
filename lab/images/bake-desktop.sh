#!/usr/bin/env bash
# Bake a graphical XFCE workstation image for the MGMT zone (DESK01).
# Gives an operator a real desktop in GNS3 to: open the AI dashboard in Firefox,
# run the afw MCP tools against the controller, and (with lab egress enabled)
# run the Claude CLI. Baked with Internet (user-mode net) like the golden image.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DL="${DL:-$HOME/afw-lab/downloads}"
OUT="${OUT:-$HOME/GNS3/images/QEMU}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
BASE="$DL/ubuntu-24.04-minimal-cloudimg-amd64.img"
GOLD="$OUT/afw-ubuntu-desktop.qcow2"
export PATH="$HOME/.local/bin:$PATH"

cd "$ROOT"
uv export --no-dev --no-hashes --no-emit-project --format requirements-txt -q > "$WORK/requirements.txt"
uv build --wheel -q -o "$WORK/dist"
WHEEL="$(ls "$WORK"/dist/*.whl)"

mkdir -p "$OUT"
qemu-img convert -O qcow2 "$BASE" "$WORK/gold.qcow2"
qemu-img resize -q "$WORK/gold.qcow2" 16G

b64() { base64 -w0 "$1"; }
cat > "$WORK/user-data" <<UD
#cloud-config
hostname: afw-desktop
users:
  - name: afw
    groups: [sudo, adm]
    shell: /bin/bash
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    lock_passwd: true
    ssh_authorized_keys: ["$(cat "$HOME/.config/afw/lab_ed25519.pub")"]
package_update: true
packages: [xserver-xorg, xinit, xfwm4, xfce4-session, xfce4-panel, xfce4-terminal,
           xfdesktop4, xfce4-settings, lightdm, lightdm-gtk-greeter, dbus-x11,
           python3-venv, git, curl, ca-certificates, nano, net-tools, iproute2,
           iputils-ping, chrony, openssh-server, qemu-guest-agent, nodejs, npm]
write_files:
  - path: /opt/afw/dist/requirements.txt
    encoding: b64
    content: $(b64 "$WORK/requirements.txt")
  - path: /opt/afw/dist/$(basename "$WHEEL")
    encoding: b64
    content: $(b64 "$WHEEL")
  - path: /etc/lightdm/lightdm.conf.d/10-afw-autologin.conf
    content: |
      [Seat:*]
      autologin-user=afw
      autologin-user-timeout=0
      user-session=xfce
  - path: /home/afw/Desktop/AI-Dashboard.desktop
    permissions: '0755'
    content: |
      [Desktop Entry]
      Version=1.0
      Type=Application
      Name=AI-Adaptive-Firewall Dashboard
      Exec=firefox http://10.77.50.10:8080/
      Icon=firefox
      Terminal=false
  - path: /home/afw/Desktop/Test-MCP.desktop
    permissions: '0755'
    content: |
      [Desktop Entry]
      Version=1.0
      Type=Application
      Name=Test the afw MCP tools
      Exec=xfce4-terminal --title "afw MCP" -e "bash -lc '/opt/afw/bin/mcp-tools; exec bash'"
      Icon=utilities-terminal
      Terminal=false
  - path: /opt/afw/bin/mcp-tools
    permissions: '0755'
    content: |
      #!/usr/bin/env bash
      # Offline-capable MCP tool test: spawns the afw MCP server (stdio) and calls
      # a couple of read-only tools against the controller. No Anthropic account
      # needed (this exercises the MCP server + controller, not the Claude chat).
      export AFW_API_URL=\${AFW_API_URL:-http://10.77.50.10:8080}
      export AFW_MCP_TOKEN_FILE=\${AFW_MCP_TOKEN_FILE:-\$HOME/.config/afw/api/mcp.token}
      exec /opt/afw/venv/bin/python /opt/afw/bin/mcp_client.py "\$@"
  - path: /opt/afw/bin/mcp_client.py
    content: |
      import anyio, os
      from mcp import ClientSession, StdioServerParameters
      from mcp.client.stdio import stdio_client
      async def main():
          env = {**os.environ,
                 "AFW_API_URL": os.environ.get("AFW_API_URL", "http://10.77.50.10:8080"),
                 "AFW_MCP_TOKEN_FILE": os.environ.get("AFW_MCP_TOKEN_FILE",
                     os.path.expanduser("~/.config/afw/api/mcp.token"))}
          params = StdioServerParameters(command="/opt/afw/venv/bin/afw-mcp", env=env)
          async with stdio_client(params) as (r, w):
              async with ClientSession(r, w) as s:
                  await s.initialize()
                  tools = await s.list_tools()
                  print("MCP connected. tools:", len(tools.tools))
                  for name in ("lab_health", "overview"):
                      try:
                          res = await s.call_tool(name, {})
                          txt = res.content[0].text if res.content else ""
                          print(f"\n== {name} ==\n" + txt[:600])
                      except Exception as e:
                          print(f"{name}: {e}")
      anyio.run(main)
  - path: /home/afw/README-test.txt
    content: |
      AI-Adaptive-Firewall - operator desktop (MGMT zone)
      ===================================================
      * Dashboard: double-click "AI-Dashboard" (Firefox -> http://10.77.50.10:8080).
        Paste the viewer token when asked (see ~/.config/afw/api/dashboard.token).
      * MCP tools (offline): double-click "Test the afw MCP tools", or run
        /opt/afw/bin/mcp-tools  (lists tools + calls lab_health/overview).
      * Claude CLI (needs Internet egress + your login): run  claude  then
        'claude mcp list' should show 'afw' Connected; ask it to use the tools.
      * Project repo lives in ~/ai-adaptive-firewall.
runcmd:
  - [bash, -c, "python3 -m venv /opt/afw/venv && /opt/afw/venv/bin/pip install -q -r /opt/afw/dist/requirements.txt && /opt/afw/venv/bin/pip install -q --no-deps /opt/afw/dist/*.whl"]
  - [bash, -c, "install -d -m0755 /etc/apt/keyrings && curl -fsSL https://packages.mozilla.org/apt/repo-signing-key.gpg -o /etc/apt/keyrings/packages.mozilla.org.asc && echo 'deb [signed-by=/etc/apt/keyrings/packages.mozilla.org.asc] https://packages.mozilla.org/apt mozilla main' > /etc/apt/sources.list.d/mozilla.list && printf 'Package: *\\nPin: origin packages.mozilla.org\\nPin-Priority: 1000\\n' > /etc/apt/preferences.d/mozilla && apt-get update && apt-get install -y firefox"]
  - [bash, -c, "npm install -g @anthropic-ai/claude-code || echo 'claude install skipped'"]
  - [bash, -c, "mkdir -p /home/afw/.config/afw/api /home/afw/Desktop && chown -R afw:afw /home/afw /opt/afw/bin 2>/dev/null; chmod +x /opt/afw/bin/* || true"]
  - [bash, -c, "systemctl set-default graphical.target && systemctl enable lightdm"]
  - [bash, -c, "echo 'net.ipv6.conf.all.disable_ipv6=1' > /etc/sysctl.d/90-afw.conf"]
  - [bash, -c, "/opt/afw/venv/bin/python -c 'import afw, mcp; print(\"AFW_DESKTOP_BAKE_OK\", afw.__version__)' > /dev/ttyS0"]
  - [bash, -c, "cloud-init clean --logs --machine-id && apt-get clean && fstrim -av || true"]
  - [poweroff]
UD
printf 'instance-id: afw-desktop-bake\nlocal-hostname: afw-desktop\n' > "$WORK/meta-data"
cloud-localds "$WORK/seed.iso" "$WORK/user-data" "$WORK/meta-data"

echo "[bake] booting desktop image build (several minutes)"
timeout 2400 qemu-system-x86_64 -enable-kvm -cpu host -smp 4 -m 4096 -nographic \
  -drive file="$WORK/gold.qcow2",if=virtio,discard=unmap \
  -drive file="$WORK/seed.iso",if=virtio,media=cdrom \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
  -serial mon:stdio | tee "$WORK/console.log" | grep --line-buffered -E 'AFW_DESKTOP_BAKE_OK|Cloud-init.*finished|rror' || true

grep -q AFW_DESKTOP_BAKE_OK "$WORK/console.log" || { echo "[bake] FAILED — see console log"; cp "$WORK/console.log" "$OUT/desktop-bake-failed.log"; exit 1; }
qemu-img convert -O qcow2 -c "$WORK/gold.qcow2" "$GOLD.tmp" && mv "$GOLD.tmp" "$GOLD"
sha256sum "$GOLD" | tee "$GOLD.sha256"
echo "[bake] desktop image: $GOLD"
