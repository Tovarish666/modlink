#!/usr/bin/env bash
# provision-vm.sh — create the ProxyVeth agent VM on Proxmox, from scratch.
#
# Run on the PROXMOX HOST as root. It:
#   1. downloads a Debian 12 cloud image (cached),
#   2. creates a VM with cloud-init (user, our SSH key, management NIC, guest agent),
#   3. boots it, waits for the guest agent, learns its IP,
#   4. over SSH: apt update/upgrade, installs deps + the pvagent service,
#   5. sets up the agent VM -> Proxmox host SSH key (so the agent can drive qm/QMP
#      to attach QEMU usb-net devices to the Windows VMs),
#   6. prints how the Windows .exe reaches the agent's HTTP API.
#
# Everything below is overridable via environment variables. Re-running with the
# same VMID is refused unless FORCE=1 (which destroys the old VM first).
#
#   Пример:  VMID=9000 BRIDGE=vmbr0 AGENT_IP=192.168.99.10/24 GW=192.168.99.1 \
#            ./provision-vm.sh
set -euo pipefail

# ------------------------------------------------------------------ config
VMID=${VMID:-9000}
VMNAME=${VMNAME:-pvagent}
STORAGE=${STORAGE:-local-lvm}          # where the VM disk lives
BRIDGE=${BRIDGE:-vmbr0}                 # management network the .exe reaches
CORES=${CORES:-2}
MEM=${MEM:-2048}
DISK=${DISK:-8G}
CIUSER=${CIUSER:-pvagent}
# Static mgmt address is strongly recommended for an agent; else set AGENT_IP=dhcp
AGENT_IP=${AGENT_IP:-dhcp}             # e.g. 192.168.99.10/24
GW=${GW:-}                             # e.g. 192.168.99.1 (required if AGENT_IP is static)
IMG_URL=${IMG_URL:-https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2}
REPO_URL=${REPO_URL:-https://github.com/Tovarish666/modlink.git}
REPO_REF=${REPO_REF:-app-v2}
HOST_SSHKEY=${HOST_SSHKEY:-/root/.ssh/id_ed25519.pub}   # host -> VM (must exist)
FORCE=${FORCE:-0}

need() { command -v "$1" >/dev/null || { echo "missing tool: $1"; exit 1; }; }
need qm; need wget; need ssh; need ssh-keygen
[ -f "$HOST_SSHKEY" ] || { echo "no host public key at $HOST_SSHKEY — run: ssh-keygen -t ed25519"; exit 1; }
[ "$AGENT_IP" = dhcp ] || [ -n "$GW" ] || { echo "static AGENT_IP set but GW empty"; exit 1; }

# ------------------------------------------------------------------ guard
if qm status "$VMID" >/dev/null 2>&1; then
  if [ "$FORCE" = 1 ]; then echo "FORCE=1: destroying old VM $VMID"; qm stop "$VMID" || true; sleep 2; qm destroy "$VMID" --purge;
  else echo "VM $VMID already exists (set FORCE=1 to recreate)"; exit 1; fi
fi

# ------------------------------------------------------------------ image
cache=/var/lib/vz/template/iso
mkdir -p "$cache"
img="$cache/$(basename "$IMG_URL")"
[ -f "$img" ] || { echo "downloading $IMG_URL"; wget -q --show-progress -O "$img" "$IMG_URL"; }

# ------------------------------------------------------------------ create
echo "creating VM $VMID ($VMNAME)"
qm create "$VMID" --name "$VMNAME" --memory "$MEM" --cores "$CORES" --ostype l26 \
   --scsihw virtio-scsi-single --net0 "virtio,bridge=$BRIDGE" --agent enabled=1
# import-from needs Proxmox 7.2+; on older use: qm importdisk + qm set --scsi0
qm set "$VMID" --scsi0 "$STORAGE:0,import-from=$img"
qm set "$VMID" --boot order=scsi0 --serial0 socket --vga serial0
qm disk resize "$VMID" scsi0 "$DISK"

# ------------------------------------------------------------------ cloud-init
qm set "$VMID" --ide2 "$STORAGE:cloudinit"
qm set "$VMID" --ciuser "$CIUSER" --sshkeys "$HOST_SSHKEY"
if [ "$AGENT_IP" = dhcp ]; then qm set "$VMID" --ipconfig0 "ip=dhcp"
else                            qm set "$VMID" --ipconfig0 "ip=$AGENT_IP,gw=$GW"; fi

echo "starting VM $VMID"
qm start "$VMID"

# ------------------------------------------------------------------ wait + IP
echo -n "waiting for guest agent"
for i in $(seq 1 60); do
  if qm agent "$VMID" ping >/dev/null 2>&1; then echo " ok"; break; fi
  echo -n .; sleep 5
  [ "$i" = 60 ] && { echo; echo "guest agent never came up"; exit 1; }
done
VMIP=$(qm agent "$VMID" network-get-interfaces 2>/dev/null \
  | grep -oE '"ip-address"\s*:\s*"[0-9.]+"' | grep -oE '[0-9.]+' \
  | grep -vE '^127\.' | head -1)
[ -n "$VMIP" ] || { echo "could not learn VM IP"; exit 1; }
echo "agent VM IP: $VMIP"

SSH="ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 $CIUSER@$VMIP"
echo -n "waiting for ssh"
for i in $(seq 1 30); do $SSH true >/dev/null 2>&1 && { echo " ok"; break; }; echo -n .; sleep 4; done

# ------------------------------------------------------------------ install
echo "installing deps + pvagent inside the VM"
$SSH "sudo bash -s" <<EOF
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get -y -q upgrade
# routing/tunnel stack lives here, on Linux, where it is reliable:
#   dnsmasq  — per-subnet DHCP (hands the Windows guest 192.168.N.100, gw .1)
#   redsocks — transparent TCP -> upstream SOCKS5 (the remote modem's proxy)
#   git/build — to build/run pvagent from the repo
apt-get -y -q install git curl ca-certificates iproute2 iptables dnsmasq redsocks build-essential
systemctl disable --now dnsmasq || true   # pvagent manages per-subnet instances itself
install -d /opt/proxyveth
git clone --depth 1 -b "$REPO_REF" "$REPO_URL" /opt/proxyveth/src || \
  (cd /opt/proxyveth/src && git pull)
# pvagent itself is the next deliverable; scaffold its home + service now.
install -d /etc/proxyveth
if [ -x /opt/proxyveth/src/agent/install.sh ]; then
  /opt/proxyveth/src/agent/install.sh
else
  echo "NOTE: agent/install.sh not present yet — VM is provisioned, pvagent pending."
fi
EOF

# ------------------------------------------------------------------ VM -> host key
echo "setting up agent VM -> Proxmox host SSH (for qm/QMP)"
$SSH "test -f ~/.ssh/id_ed25519 || ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_ed25519 -q"
VMPUB=$($SSH "cat ~/.ssh/id_ed25519.pub")
grep -qF "$VMPUB" /root/.ssh/authorized_keys 2>/dev/null || echo "$VMPUB" >> /root/.ssh/authorized_keys
echo "  agent VM can now ssh root@<this host> to run qm/QMP"

# ------------------------------------------------------------------ done
cat <<DONE

==== done ====
Agent VM:     $VMNAME (id $VMID)  ip $VMIP
Reach it:     ssh $CIUSER@$VMIP
Control API:  the Windows .exe will call  http://$VMIP:8787/   (once pvagent runs)
Next:         build pvagent (HTTP API + QEMU usb-net + DHCP + SOCKS5 exit).
DONE
