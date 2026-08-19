#!/usr/bin/env bash
# Install single-node OpenShift on the shared chapter-4 box. Runs on the WORKSTATION.
#
#   ./install.sh --preflight        every check that costs nothing. Run this FIRST.
#   ./install.sh                    the whole thing, ending in a cluster lessons 1.4.1–1.4.4 can use
#   ./install.sh --from kexec       resume at a stage (the ids come from stages.json)
#   ./install.sh --facts            just re-print the box's facts
#   ./install.sh --status           cluster version + any degraded operators
#
# Every run appends to .state/openshift-sno-<utc>.log. That is not a nicety: this box has no console
# below the paid BMC tier, so when an install goes dark the log is the entire post-mortem, and
# rules/06-testing.md asks for exactly this ("redirect the whole run to a file"). Nothing wrote one
# before, and the 2026-08-05 failure was diagnosed from scrollback that happened to still be open.
# The same call (lib.sh's run_track) also opens the event stream, so a run typed by hand is watchable
# stage by stage from `../ctl.py status openshift-sno` or the panel — two hours is far too long to
# have to guess. Started FROM ctl.py instead, the supervisor owns both files and writes its own.
#
# WHY THIS IS NOT A SUBSTRATE. Every other boundary in this repo installs onto a box and leaves it
# recognisable, so `up.sh` can ssh in as `agent` and run a script. This one REPLACES THE OPERATING
# SYSTEM mid-flight: the machine that finishes is RHCOS, with no `agent` user, no repo checkout and
# no uv. There is nothing for the substrate model to hold on to, so the orchestration lives here and
# only the *artifacts* (a 109 KB ignition) are pushed to the box.
#
# THE FAILURE THIS SCRIPT EXISTS TO PREVENT (OPTIMIZATIONS.md §9, the 2026-08-05 run):
# RHCOS installed perfectly onto the disk the BIOS does not boot, the box came back up in Ubuntu,
# and no log anywhere said "wrong disk". Two independent causes, both handled below:
#   1. kernel device names are NOT stable across kernels — Ubuntu's sda was RHCOS-live's sdb — so
#      the install disk is pinned by WWN, which is a property of the device and not of the kernel.
#   2. the other disk kept a bootable Ubuntu, so the firmware had something else to choose. The
#      ignition now carries a unit that wipes EVERY disk before install-to-disk runs, leaving the
#      machine exactly one bootable thing.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091  # path is computed from BASH_SOURCE; it exists at run time
source "${HERE}/../lib.sh"

CLUSTER=openshift-sno
OCP_VERSION=4.18.49
PULL_SECRET="${HOME}/.secrets/rh-pull-secret.json"
CFG="${HERE}/cfg"
CORE_KEY="${SSH_KEY}" # the same throwaway keypair every box in this repo trusts

# `oc` talks to the API by IP while verifying the cert's SAN — no /etc/hosts edit on the node and no
# 185 MB push (OPTIMIZATIONS.md §8, Trap #11). The SAN the installer mints is api.<name>.<baseDomain>.
API_SAN="api.sno.spike.lab"

# Captured BEFORE stdout is redirected into the run log, or the answer would always be "no" and the
# log would be the only consumer left. Bold for a human at a terminal; plain everywhere else, which
# is what keeps the log file and an agent's captured output free of escape sequences.
if [ -t 1 ]; then IS_TTY=1; else IS_TTY=0; fi

step() {
  if [ "${IS_TTY}" = "1" ]; then printf '\n\033[1m==> %s\033[0m\n' "$*"; else printf '\n==> %s\n' "$*"; fi
  emit step "$*"
  hb_reset
}
ok() {
  echo "    [OK] $*"
  hb_reset
}
#: Set by `bad`, read by `preflight`. A single failed check must not abort the rest — the whole
#: point of preflight is to report EVERY problem in one pass, before anything is billable.
FAIL=0
bad() {
  echo "    [!!] $*" >&2
  FAIL=1
}

# --- ssh to the box, whatever OS it is currently running ----------------------
#
# The user changes under us: Ubuntu logs in as `ubuntu`, RHCOS as `core`. And the host key changes
# at every reinstall/pivot/MCO reboot, which we cause, so a known-hosts entry here is pure friction
# that presents as a MITM warning (Trap #9).
box() {
  local user="$1"
  shift
  state_load "${CLUSTER}"
  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
    -o ConnectTimeout=10 -i "${CORE_KEY}" "${user}@${BOX_IP}" "$@"
}

# =============================================================================
# preflight — everything that can fail for free, before the meter starts
# =============================================================================
preflight() {
  step "Preflight (nothing here costs money)"
  FAIL=0
  # errexit OFF for the whole function, deliberately. Every line here is a CHECK, and the value of
  # a preflight is that it reports all of them in one pass. Under `set -e` the first transient
  # network blip aborts the run and you learn about exactly one problem — which is what happened
  # the first time this ran (curl exit 56 on the release notes, nothing else reported).
  set +e

  local cur
  cur=$(curl -fsSL "https://mirror.openshift.com/pub/openshift-v4/clients/ocp/stable-4.18/release.txt" 2>/dev/null | awk '/^Name:/{print $2; exit}')
  if [ "${cur}" = "${OCP_VERSION}" ]; then
    ok "stable-4.18 is still ${OCP_VERSION}"
  else
    # NOT a failure. We pin deliberately; this only reports the drift so nobody is surprised that
    # the channel has moved on while this repo stays on the version it actually proved.
    ok "stable-4.18 has moved to ${cur:-?}; staying pinned at ${OCP_VERSION} (the version that worked)"
  fi

  local code
  for a in openshift-install-mac-arm64.tar.gz openshift-client-mac-arm64.tar.gz openshift-client-linux.tar.gz; do
    code=$(curl -fsS -o /dev/null -w '%{http_code}' "https://mirror.openshift.com/pub/openshift-v4/clients/ocp/${OCP_VERSION}/${a}" 2>/dev/null || echo 000)
    if [ "${code}" = "200" ]; then ok "artifact ${a}"; else bad "artifact ${a} -> ${code}"; fi
  done

  local stock
  stock=$(scw baremetal offer list zone="${ZONE}" -o json 2>/dev/null | jq -r '.[]|select(.name=="EM-B112X-SSD")|.stock')
  if [ "${stock}" = "available" ]; then
    ok "EM-B112X-SSD stock=${stock} (EUR $(hourly_price EM-B112X-SSD baremetal)/hr)"
  else
    bad "EM-B112X-SSD stock=${stock:-unknown} — cannot order"
  fi

  # Presence only. The contents are a credential and are never printed, here or anywhere.
  if [ -r "${PULL_SECRET}" ]; then
    ok "pull secret present at ${PULL_SECRET/#$HOME/\~}"
  else
    bad "no readable pull secret at ${PULL_SECRET} — console.redhat.com/openshift/install/pull-secret"
  fi
  if [ -r "${CORE_KEY}.pub" ]; then ok "throwaway ssh key present"; else bad "no ssh key at ${CORE_KEY}.pub"; fi

  for t in openshift-install oc oc-linux; do
    if [ -x "${HERE}/${t}" ]; then ok "${t} staged"; else bad "${t} missing — fetch it before ordering"; fi
  done

  # Lesson 1.4.4's upstream deps, checked at the versions chapter 3 actually pinned.
  code=$(curl -fsS -o /dev/null -w '%{http_code}' -L "https://github.com/kubernetes-sigs/agent-sandbox/releases/download/v0.5.4/sandbox.yaml" 2>/dev/null || echo 000)
  if [ "${code}" = "200" ]; then ok "agent-sandbox v0.5.4"; else bad "agent-sandbox v0.5.4 -> ${code}"; fi
  if helm show chart oci://ghcr.io/nvidia/openshell/helm-chart --version 0.0.99 >/dev/null 2>&1; then
    ok "openshell chart 0.0.99"
  else
    bad "openshell chart 0.0.99 unavailable"
  fi

  set -e
  [ "${FAIL}" -eq 0 ] || die "preflight FAILED — fix the above before spending anything"
  step "Preflight passed. Everything after this point is billable at EUR $(hourly_price EM-B112X-SSD baremetal)/hr."
}

# =============================================================================
# provision — a plain scw baremetal create, tracked in .state so down.sh --all always finds it
# =============================================================================
provision() {
  step "Provisioning ${CLUSTER} (EM-B112X-SSD)"
  require_key
  if [ -f "$(state_file "${CLUSTER}")" ]; then
    state_load "${CLUSTER}"
    ok "already provisioned: ${BOX_ID} (${BOX_IP})"
    return 0
  fi
  # box_create dispatches on kind=baremetal (lessons.json) and writes .state/openshift-sno.env. NOTE:
  # the metal path was migrated off Terraform but not live-verified — a metal box is EUR 0.263/hr and
  # a ~15-min OS install, so it is not provisioned casually. Confirm on the next real cluster build.
  box_create "${CLUSTER}"
  state_load "${CLUSTER}"
  ok "${BOX_USER}@${BOX_IP} (${BOX_ID})"
  # Metal reports `status: ready` when the HARDWARE is allocated; the OS install is tracked
  # separately and finishes minutes later (Trap #8). Terraform waits on the install, but sshd still
  # flaps afterwards, so require two consecutive successes.
  local ok_count=0 expect
  expect=$(stage_expect openshift-sno provision)
  for _ in $(seq 1 90); do
    if box ubuntu true 2>/dev/null; then
      ok_count=$((ok_count + 1))
      [ "${ok_count}" -ge 2 ] && {
        ok "ssh answering as ubuntu"
        return 0
      }
    else
      ok_count=0
    fi
    hb "${expect}"
    sleep 10
  done
  die "ssh to the box never came up. If ping works but ssh hangs this is the MTU trap (Trap #1):
       sudo ifconfig \$(route -n get default | awk '/interface/{print \$2}') mtu 1400"
}

# =============================================================================
# facts — the readings that decide the whole install
# =============================================================================
facts() {
  step "Capturing the facts the install depends on"
  mkdir -p "${CFG}"
  # shellcheck disable=SC2016  # single-quoted on purpose: this must expand on the box, not here
  box ubuntu 'set -e
    echo "ADDR_CIDR=$(ip -4 -o addr show scope global | awk "{print \$4; exit}")"
    echo "FIRMWARE=$([ -d /sys/firmware/efi ] && echo UEFI || echo BIOS)"
    echo "BOOT_SRC=$(findmnt -no SOURCE /boot 2>/dev/null || echo none)"
    echo "NPROC=$(nproc)"
    echo "MEM_GB=$(awk "/MemTotal/{print int(\$2/1048576)}" /proc/meminfo)"
    echo "KVM=$([ -e /dev/kvm ] && echo present || echo ABSENT)"
    lsblk -dno NAME,SIZE,WWN | awk "{print \"DISK=\\\"\" \$1 \" \" \$2 \" \" \$3 \"\\\"\"}"
  ' >"${CFG}/facts.env"
  sed 's/^/    /' "${CFG}/facts.env"

  # shellcheck disable=SC1091
  ADDR_CIDR=$(awk -F= '/^ADDR_CIDR=/{print $2}' "${CFG}/facts.env")
  MACHINE_CIDR="$(echo "${ADDR_CIDR}" | cut -d. -f1-3).0/$(echo "${ADDR_CIDR}" | cut -d/ -f2)"

  # The WWN of the disk RHCOS will be installed to. Pinned by WWN and NOT by /dev/sdX, because that
  # name is resolved by the RHCOS-live kernel and the two kernels disagreed on this exact box.
  #
  # `tr -d '"'` is not cosmetic. The DISK lines are quoted so facts.env stays shell-sourceable, and
  # awk's $3 therefore ends with the closing quote — which sailed straight through into
  # `installationDisk: /dev/disk/by-id/wwn-0x5001b448b798588b"`, a path no device will ever match.
  INSTALL_WWN=$(awk '/^DISK=/{print $3; exit}' "${CFG}/facts.env" | tr -d '"')

  # VALIDATE the shape, do not merely check it is non-empty. This value's whole job is to be a real
  # device path an hour from now, in a different kernel, with no console to debug from — and the
  # 2026-08-05 failure is precisely what a wrong-but-plausible disk reference costs. A malformed one
  # must fail here, while the fix is free, not silently become an install that goes nowhere.
  case "${INSTALL_WWN}" in
    0x[0-9a-f]*) : ;;
    *) die "WWN '${INSTALL_WWN}' is not of the form 0x<hex> — refusing to pin installationDisk to it" ;;
  esac

  {
    echo "MACHINE_CIDR=${MACHINE_CIDR}"
    echo "INSTALL_WWN=${INSTALL_WWN}"
  } >>"${CFG}/facts.env"
  ok "machineNetwork ${MACHINE_CIDR}"
  ok "installationDisk /dev/disk/by-id/wwn-${INSTALL_WWN}"
  if grep -q "KVM=present" "${CFG}/facts.env"; then
    ok "/dev/kvm present — Kata can work here"
  else
    die "/dev/kvm ABSENT — this box cannot run Kata, which is lesson 1.4.3's whole point"
  fi
}

# =============================================================================
# ignition — generated here, wrapped here, 109 KB pushed to the box
# =============================================================================
ignition() {
  step "Generating the bootstrap ignition"
  # Read the two values rather than `source` the file. facts.env is a human-readable log that also
  # carries multi-word `DISK="sda 894G 0x..."` lines, and sourcing it once blew up on an unquoted
  # size (`894.3G: command not found`). Extracting exactly what is needed cannot break that way.
  local MACHINE_CIDR INSTALL_WWN
  MACHINE_CIDR=$(awk -F= '/^MACHINE_CIDR=/{print $2}' "${CFG}/facts.env")
  INSTALL_WWN=$(awk -F= '/^INSTALL_WWN=/{print $2}' "${CFG}/facts.env")
  [ -n "${MACHINE_CIDR}" ] && [ -n "${INSTALL_WWN}" ] || die "facts.env is missing MACHINE_CIDR/INSTALL_WWN — run --facts first"
  rm -rf "${CFG}/gen" && mkdir -p "${CFG}/gen"

  # The pull secret is inlined into a file under cfg/ (gitignored) and never echoed.
  sed -e "s|__MACHINE_CIDR__|${MACHINE_CIDR}|" \
    -e "s|__PULL_SECRET__|$(jq -c . "${PULL_SECRET}" | sed 's/[&|]/\\&/g')|" \
    -e "s|__SSH_PUBKEY__|$(cat "${CORE_KEY}.pub")|" \
    "${HERE}/install-config.template.yaml" >"${CFG}/gen/install-config.yaml"
  # Replace the template's /dev/sda with the WWN path — the entire point of this run.
  sed -i '' -e "s|installationDisk: .*|installationDisk: /dev/disk/by-id/wwn-${INSTALL_WWN}|" \
    "${CFG}/gen/install-config.yaml" 2>/dev/null \
    || sed -i -e "s|installationDisk: .*|installationDisk: /dev/disk/by-id/wwn-${INSTALL_WWN}|" "${CFG}/gen/install-config.yaml"
  grep -n "installationDisk\|machineNetwork" -A1 "${CFG}/gen/install-config.yaml" | grep -v pullSecret | sed 's/^/    /'

  # Two-step generation, because a day-1 manifest has to be injected between the steps. `create
  # manifests` consumes install-config.yaml and renders the manifests/ + openshift/ trees; anything
  # dropped into openshift/ before the ignition step is bundled into bootstrap exactly like the
  # MachineConfigs the installer generates itself.
  "${HERE}/openshift-install" --dir="${CFG}/gen" create manifests
  grep -rq 'baselineCapabilitySet: None' "${CFG}/gen/manifests" \
    || die "the capability trim did not reach the rendered manifests — check install-config.template.yaml"
  ok "manifests rendered, payload trimmed (baselineCapabilitySet: None)"

  # The kata extension, day 1. This deletes the old install's single largest avoidable block — the
  # operator's day-2 MachineConfig rollout and its ~19-min node reboot. Why it is safe and how the
  # no-op is achieved: manifests/day1-kata-extension.yaml.
  cp "${HERE}/manifests/day1-kata-extension.yaml" \
    "${CFG}/gen/openshift/99_openshift-machineconfig_50-enable-sandboxed-containers-extension.yaml"
  ok "kata extension MachineConfig injected as a day-1 manifest"

  "${HERE}/openshift-install" --dir="${CFG}/gen" create single-node-ignition-config
  local ign="${CFG}/gen/bootstrap-in-place-for-live-iso.ign"
  [ -s "${ign}" ] || die "no ignition produced"

  # PROVE the extension reached the ignition rather than trusting the cp above. Every file payload
  # in the ignition is base64, most gzipped first, so a plain grep of the JSON finds nothing —
  # the false all-clear OPTIMIZATIONS.md §10 warns about, in both directions.
  local src tmp="${CFG}/gen/.payload" found=0
  while IFS= read -r src; do
    printf '%s' "${src}" | base64 -d >"${tmp}" 2>/dev/null || continue
    if gzip -dc "${tmp}" 2>/dev/null | grep -q 'sandboxed-containers' || grep -q 'sandboxed-containers' "${tmp}"; then
      found=1
      break
    fi
  done < <(jq -r '.storage.files[]?.contents.source // empty' "${ign}" | sed -n 's/^data:[^,]*;base64,//p')
  rm -f "${tmp}"
  [ "${found}" = "1" ] || die "no decoded ignition payload mentions the sandboxed-containers extension — the day-1 MachineConfig was dropped"
  ok "ignition $(wc -c <"${ign}") bytes; kata extension verified inside; auth/ written"

  step "Injecting the disk-wipe unit (the fix for the 2026-08-05 failure)"
  # Runs in the LIVE environment, in RAM, before install-to-disk touches anything. It stops every
  # md array and wipes every whole disk, so that (a) the target is genuinely free — Trap #7 — and
  # (b) nothing else on the machine is bootable, which is what actually went wrong last time: a
  # perfect RHCOS install is invisible if the firmware has a leftover Ubuntu to boot instead.
  local unit
  unit=$(
    cat <<'UNIT'
[Unit]
Description=Wipe every disk before bootstrap-in-place installs
DefaultDependencies=false
After=basic.target
Before=install-to-disk.service
[Service]
Type=oneshot
RemainAfterExit=true
ExecStart=/bin/bash -c 'set -x; mdadm --stop --scan || true; dmsetup remove_all || true; for d in /sys/block/sd* /sys/block/nvme*; do [ -e "$d" ] || continue; n=/dev/$(basename $d); wipefs -a "$n" || true; sgdisk --zap-all "$n" || true; dd if=/dev/zero of="$n" bs=1M count=16 oflag=direct || true; done; udevadm settle || true'
[Install]
WantedBy=multi-user.target
UNIT
  )
  jq --arg c "${unit}" '.systemd.units += [{"name":"sbx-wipe-disks.service","enabled":true,"contents":$c}]' \
    "${ign}" >"${ign}.new" && mv "${ign}.new" "${ign}"
  jq -e '.systemd.units[] | select(.name=="sbx-wipe-disks.service")' "${ign}" >/dev/null \
    || die "the wipe unit did not land in the ignition"
  ok "sbx-wipe-disks.service injected, ordered Before=install-to-disk.service"

  step "Wrapping the ignition on this machine (deletes Traps #3 and #4)"
  # coreos-installer publishes linux/arm64, so the wrap runs natively here and the node never needs
  # a container runtime — which is the only reason the old runbook went through rescue at all.
  (cd "${CFG}/gen" && podman run --rm --arch arm64 -v "$PWD":/data:z -w /data \
    quay.io/coreos/coreos-installer:release pxe ignition wrap -i /data/bootstrap-in-place-for-live-iso.ign -o /data/ign.img)
  [ -s "${CFG}/gen/ign.img" ] || die "wrap produced no ign.img"
  ok "ign.img $(wc -c <"${CFG}/gen/ign.img") bytes"
}

# =============================================================================
# kexec — jump into RHCOS live in RAM; the wipe unit and install-to-disk do the rest
# =============================================================================
kexec_live() {
  step "Pushing the ignition and kexec'ing into RHCOS live"
  state_load "${CLUSTER}"
  scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
    -i "${CORE_KEY}" "${CFG}/gen/ign.img" "ubuntu@${BOX_IP}:/var/tmp/ign.img"
  ok "ign.img on the box"

  # Derived from the installer, never from the mirror index (OPTIMIZATIONS.md §6): the mirror's
  # "latest" directory can hold a build the pinned installer does not expect.
  local urls kernel initramfs rootfs
  urls=$("${HERE}/openshift-install" coreos print-stream-json \
    | jq -r '.architectures.x86_64.artifacts.metal.formats.pxe | .kernel.location, .initramfs.location, .rootfs.location')
  kernel=$(sed -n 1p <<<"${urls}")
  initramfs=$(sed -n 2p <<<"${urls}")
  rootfs=$(sed -n 3p <<<"${urls}")
  ok "RHCOS $(basename "$(dirname "${kernel}")")"

  box ubuntu "set -e
    cd /var/tmp
    command -v kexec >/dev/null || { sudo DEBIAN_FRONTEND=noninteractive apt-get -qq update; sudo DEBIAN_FRONTEND=noninteractive apt-get -qq install -y kexec-tools; }
    curl -fsSL '${kernel}'    -o kernel
    curl -fsSL '${initramfs}' -o initramfs.img
    cat initramfs.img ign.img > boot.img
    echo \"    kernel=\$(stat -c%s kernel) boot.img=\$(stat -c%s boot.img)\"
    sudo kexec -l kernel --initrd=boot.img --append='coreos.live.rootfs_url=${rootfs} ignition.firstboot ignition.platform.id=metal rd.neednet=1 ip=dhcp'
    sudo bash -c 'nohup sh -c \"sleep 2; kexec -e\" >/dev/null 2>&1 &'
    echo '    kexec -e scheduled'
  "
  ok "jumped — ssh will drop; the box is now RHCOS live in RAM"
}

# =============================================================================
# api — poll actual state, never just wait (REPRODUCE.md §3b)
# =============================================================================
# One HTTP status from the API, and ALWAYS exactly one token. `curl -w %{http_code}` prints 000 AND
# exits non-zero when nothing answers, so the obvious `$(curl ... || echo 000)` yields "000000".
api_status() {
  state_load "${CLUSTER}"
  local out
  out=$(curl -k -s -o /dev/null -m 5 -w '%{http_code}' "https://${BOX_IP}:6443/healthz" 2>/dev/null | tail -1)
  echo "${out:-000}"
}

# A PROBE, so it must never abort the caller. `|| true` is load-bearing under `set -e`: this is
# called as `s="$(node_ssh ...)"`, and a failed command substitution in a plain assignment exits the
# whole script. The box being unreachable is the NORMAL state here — it is mid-kexec or mid-pivot —
# so the one moment this function is most useful is the moment it would otherwise kill the run.
# Measured: the wait died with exit 255 on its very first poll, before the "ssh-no-answer (expected
# once)" branch that exists precisely to handle it could ever execute.
node_ssh() {
  state_load "${CLUSTER}"
  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
    -o ConnectTimeout=8 -i "${CORE_KEY}" "core@${BOX_IP}" "$@" 2>/dev/null || true
}

# Give the NODE the cluster's own API names. Trap #10, and the half of it that is easy to drop.
#
# SNO with `platform: none` ships no DNS. OPTIMIZATIONS.md §8 removes the need to edit /etc/hosts for
# the CLIENT — `tls-server-name` lets `oc` verify api.sno.spike.lab while connecting to the IP — and
# it is tempting to conclude the /etc/hosts step is therefore obsolete. It is not. The **kubelet**
# resolves `api-int.sno.spike.lab` to register the node, and nothing else provides that name:
#
#     Unable to register node with API server:
#       Post "https://api-int.sno.spike.lab:6443/api/v1/nodes":
#       dial tcp: lookup api-int.sno.spike.lab ... no such host
#
# The symptom is a cluster that looks alive — the API answers, `clusterversion` exists — while
# `oc get nodes` returns "No resources found" and the rollout sits at the same percentage forever.
# Measured on 2026-08-10: stuck at 541/906 for 37 minutes until this ran.
node_dns() {
  step "Giving the node its own API names (Trap #10 — the kubelet needs them, not just us)"
  state_load "${CLUSTER}"
  # shellcheck disable=SC2016  # expands on the node, not here
  node_ssh "grep -q api-int /etc/hosts || echo '${BOX_IP} api.sno.spike.lab api-int.sno.spike.lab' | sudo tee -a /etc/hosts >/dev/null
    sudo systemctl restart kubelet"
  if [ -n "$(node_ssh 'getent hosts api-int.sno.spike.lab')" ]; then
    ok "api-int.sno.spike.lab resolves on the node; kubelet restarted"
  else
    die "the node still cannot resolve api-int.sno.spike.lab — it will never register"
  fi
}

# The same repair, quiet and repeatable, for use INSIDE the convergence loop.
#
# Calling node_dns() once is not enough and that cost the most time of any fault here: /etc/hosts
# does NOT survive the reboots this install causes. The entries were written at 16:43 and gone by
# 17:03, wiped by the pivot and then by the MCO applying the final MachineConfig. Without the name
# the kubelet cannot reach api-int, so it never submits a CSR, so the node never registers, so the
# wait never ends — a deadlock in which every component looks healthy on its own.
#
# Restoring it produced a CSR four seconds later. So the loop re-checks rather than trusting a repair
# made before a reboot it knows is coming.
node_dns_repair() {
  state_load "${CLUSTER}"
  # shellcheck disable=SC2016  # expands on the node, not here
  local out
  out=$(node_ssh "grep -q api-int /etc/hosts && echo present || {
      echo '${BOX_IP} api.sno.spike.lab api-int.sno.spike.lab' | sudo tee -a /etc/hosts >/dev/null
      sudo systemctl restart kubelet
      echo repaired; }")
  case "${out}" in *repaired*) echo "    [$(date +%H:%M:%S)] /etc/hosts had been wiped by a reboot — restored, kubelet restarted" ;; esac
}

# The three phases of the hour-long `api` stage, in order, as declared in stages.json. Moving to one
# is FORWARD-ONLY, which is not tidiness: the wait loop's first reading is routinely `ssh-no-answer`
# (RHCOS live has not finished starting sshd), and a classifier that read that as "the pivot reboot"
# would report the last phase in the first minute and then walk backwards. Ordering makes that
# unrepresentable rather than something to remember.
API_SUBSTAGES="bootkube install-to-disk operators"

api_sub() {
  local want="$1" i=0 wi=-1 ci=-1 s
  for s in ${API_SUBSTAGES}; do
    [ "${s}" = "${want}" ] && wi=${i}
    [ "${s}" = "${SBX_SUB}" ] && ci=${i}
    i=$((i + 1))
  done
  # Also covers "already in it": a phase is entered once, and its clock runs from that moment.
  [ "${wi}" -gt "${ci}" ] || return 0
  substage_begin "${want}" "$(jq -r --arg s "${want}" \
    'first(."openshift-sno".stages[] | select(.id == "api") | .substages[] | select(.id == $s) | .title) // $s' \
    "${STAGES_JSON}")"
}

wait_api() {
  step "Waiting for bootstrap-in-place to finish, then for the REAL cluster"
  api_sub bootkube
  # THE API ANSWERING IS NOT THE FINISH LINE, and mistaking it for one is how this script first
  # reported "Cluster is up" over `oc get clusterversion` -> "No resources found".
  #
  # During bootstrap-in-place there are TWO control planes on the same address. bootkube stands a
  # temporary one up in RAM and serves :6443 from it within minutes; only later does install-to-disk
  # write the permanent system, the machine pivot-reboots, and the real cluster start answering on
  # the same port. Polling /healthz alone cannot tell them apart — so poll for the things that only
  # the real one produces.
  # TWO terminal conditions, because no single one covers the whole timeline. `.bootkube.done` is the
  # marker while bootkube runs — from the INSTALLED disk, not from RAM — but the final pivot reboot
  # DELETES /opt/openshift along with the rest of the bootstrap artifacts, so after that it can never
  # appear again. Waiting on it alone burns 45 minutes on an already-finished cluster, which is
  # exactly what `--from api` is reached for.
  #
  # So also break when the real cluster answers: a registered node is proof bootstrap is over,
  # whatever the filesystem says. Both were measured on this box — `done=yes` at 14:44 during
  # bootstrap, `done=no` at 16:52 on the pivoted system, same healthy cluster.
  #
  # Do NOT replace either with a cheaper-looking "has it pivoted" test. `/run/ostree-booted` was
  # tried and is wrong: it is true from the moment the disk boots, which is the START of the
  # bootstrap phase. It made this wait skip a cluster that was 4 minutes in, and the operator loop
  # below then searched for operators that could not exist yet.
  local last="" s kc_early
  kc_early=$(kubeconfig_local)
  for _ in $(seq 1 90); do
    # shellcheck disable=SC2016  # single-quoted on purpose: this must expand on the node, not here
    s="$(node_ssh 'printf "bootkube=%s i2d=%s done=%s uptime=%s" \
        "$(systemctl is-active bootkube.service)" \
        "$(systemctl is-active install-to-disk.service)" \
        "$([ -f /opt/openshift/.bootkube.done ] && echo yes || echo no)" \
        "$(cut -d. -f1 /proc/uptime)"; true')"
    [ -z "${s}" ] && s="ssh-no-answer (pivot reboot in progress — expected once)"
    local seen
    seen=$(KUBECONFIG="${kc_early}" "${HERE}/oc" get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ' || true)
    s="${s} api-nodes=${seen}"
    [ "${s}" != "${last}" ] && {
      echo "    [$(date +%H:%M:%S)] ${s}"
      last="${s}"
    }
    case "${s}" in *"done=yes"*) break ;; esac
    [ "${seen:-0}" -gt 0 ] && {
      ok "the real cluster is answering and a node is registered — bootstrap is over"
      break
    }
    sleep 30
  done

  node_dns

  step "Waiting for the node to register and the operators to roll out"
  # NOT `clusterversion Available=True` — on THIS cluster that condition is unsatisfiable by design,
  # and waiting for it would time out after an hour on a perfectly good cluster.
  #
  # `*.apps.<domain>` wildcard DNS is deliberately skipped (Trap #10), so `authentication` (and,
  # before the payload trim, `console`) can never finish, and clusterversion sits at "Unable to
  # apply 4.18.49: MultipleErrors" forever. REPRODUCE.md §3.5 already says to accept that and
  # proceed; this encodes it instead of leaving it to a human to remember. The counts are relative
  # on purpose: the trimmed payload (install-config `capabilities`) ships fewer operators than the
  # 34 the first builds had, and `console` no longer exists at all — its name stays in the allow
  # list below so `--from api` still works against a pre-trim cluster.
  #
  # What IS required is what chapter 4 actually uses: a Ready node, and every operator that matters
  # for OLM (lesson 1.4.3 installs an operator) and for scheduling.
  local kc need_ok
  kc=$(kubeconfig_local)
  last=""
  for _ in $(seq 1 90); do
    local node avail total
    # The trailing `|| true` on each of these is load-bearing, not defensive noise. `oc get nodes`
    # exits NON-ZERO when there are no nodes, `set -o pipefail` promotes that over `head`'s 0, and a
    # failed command substitution in an assignment trips `set -e`. Without it this loop dies, in
    # silence and with exit 1, on the very state it exists to wait for: an empty cluster.
    node=$(KUBECONFIG="${kc}" "${HERE}/oc" get nodes --no-headers 2>/dev/null | awk '{print $2}' | head -1 || true)
    # The one boundary this loop can see: no node means the box is still writing the permanent
    # system, rebooting into it, or failing to resolve api-int; a node means that is all behind us
    # and what is left is the operator rollout.
    if [ -z "${node}" ]; then api_sub install-to-disk; else api_sub operators; fi
    avail=$(KUBECONFIG="${kc}" "${HERE}/oc" get co --no-headers 2>/dev/null | awk '$3=="True"' | wc -l | tr -d ' ' || true)
    total=$(KUBECONFIG="${kc}" "${HERE}/oc" get co --no-headers 2>/dev/null | wc -l | tr -d ' ' || true)
    s="node=${node:-?} operators=${avail}/${total}"
    [ "${s}" != "${last}" ] && {
      echo "    [$(date +%H:%M:%S)] ${s}"
      last="${s}"
    }
    # No node at all is the deadlock signature, not a slow rollout: if the kubelet cannot resolve
    # api-int it never submits a CSR and nothing will ever appear here. Cheap to re-check, and it
    # turns an install that hangs forever into one that repairs itself after each reboot.
    [ -z "${node}" ] && node_dns_repair
    if [ "${node}" = "Ready" ] && [ "${total}" -gt 0 ] && [ "${avail}" -ge $((total - 2)) ]; then
      # The two allowed to be missing are the DNS-blocked pair, named explicitly — "any two" would
      # happily pass a cluster whose etcd and network operators were the broken ones.
      need_ok=1
      for o in $(KUBECONFIG="${kc}" "${HERE}/oc" get co --no-headers 2>/dev/null | awk '$3!="True"{print $1}' || true); do
        case "${o}" in authentication | console | ingress) : ;; *) need_ok=0 ;; esac
      done
      [ "${need_ok}" = "1" ] && {
        ok "node Ready, ${avail}/${total} operators — only the *.apps-blocked ones are missing"
        return 0
      }
    fi
    sleep 30
  done
  die "the cluster never converged (API status now: $(api_status)).
       If \`oc get nodes\` is empty, the kubelet cannot resolve api-int — see node_dns() / Trap #10.
       If the node never appeared at all, suspect an install onto a disk the firmware does not boot:
       ssh in, and an OpenSSH banner saying 'Ubuntu' means exactly that (OPTIMIZATIONS.md §9)."
}

# Point `oc` at the IP while verifying the cert's real SAN — no /etc/hosts, no 185 MB push (§8).
kubeconfig_local() {
  local kc="${CFG}/gen/auth/kubeconfig"
  [ -s "${kc}" ] || die "no kubeconfig at ${kc}"
  state_load "${CLUSTER}"
  KUBECONFIG="${kc}" "${HERE}/oc" config set-cluster sno \
    --server="https://${BOX_IP}:6443" --tls-server-name="${API_SAN}" >/dev/null
  echo "${kc}"
}

# Storage. SNO with `platform: none` ships NO StorageClass at all, and two things in chapter 4 need
# one: the OpenShell gateway is a StatefulSet with a PVC, and every OpenShell sandbox gets a
# workspace PVC. Without this they sit Pending forever —
#
#     FailedBinding: no persistent volumes available for this claim and no storage class is set
#
# Pre-provisioned hostPath PVs rather than an operator: this box lives for one session, and
# installing LVM Storage to hold a 1 GiB sqlite file would cost more than the rest of the chapter.
#
# The SELinux relabel is the half that is easy to miss. A hostPath volume on RHCOS is denied to the
# container even at mode 777, and the failure does not mention SELinux at all — OpenShell reports
# `database error: (code: 14) unable to open database file` and CrashLoopBackOffs. `container_file_t`
# is what makes the mount writable to a container.
#
# TWO THINGS HERE WERE WRONG UNTIL 2026-08-15, and together they gave the whole chapter THREE
# sandboxes before it wedged:
#
#  1. `persistentVolumeReclaimPolicy: Delete` on a **hostPath** PV. There is no deleter plugin for
#     hostPath, so every released volume goes to `Failed` and is never reusable — `oc get pv` shows
#     `Failed` with the old claim still named. `Retain` is the only honest policy here; the volumes
#     are freed by clearing `claimRef` (see `free_pvs`), which is what a StorageClass would automate.
#  2. FOUR volumes, one of which the gateway itself takes permanently. Chapter 4 now has ten lessons
#     (1.4.1-1.4.6 and the 2.4.x audit twins) and each OpenShell sandbox binds one, so the fourth
#     sandbox of a session hung `Pending` with `unbound immediate PersistentVolumeClaims` — which
#     reads like a broken gateway and cost an hour to trace back to storage.
storage() {
  step "Pre-provisioning storage (SNO has no StorageClass)"
  local n="${1:-12}"
  local dirs=""
  for i in $(seq 0 $((n - 1))); do dirs="${dirs} /var/srv/pv${i}"; done
  # shellcheck disable=SC2086  # word splitting is the point: one mkdir for all the paths
  node_ssh "sudo mkdir -p ${dirs} && sudo chmod 777 ${dirs} && sudo chcon -Rt container_file_t ${dirs}"
  local kc
  kc=$(kubeconfig_local)
  for i in $(seq 0 $((n - 1))); do
    KUBECONFIG="${kc}" "${HERE}/oc" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: PersistentVolume
metadata: { name: sbx-pv${i} }
spec:
  capacity: { storage: 5Gi }
  accessModes: [ReadWriteOnce]
  persistentVolumeReclaimPolicy: Retain
  hostPath: { path: /var/srv/pv${i} }
EOF
  done
  free_pvs
  ok "${n} hostPath PVs available, SELinux-labelled container_file_t"
}

# Return every Released/Failed PV to Available by clearing its claimRef.
#
# With `Retain` a released volume keeps pointing at the PVC that used it and will not rebind, so
# without this a session still runs out — just more slowly. This is the one piece of housekeeping a
# real StorageClass would do for you, and running it is safe at any time: a Bound volume is untouched.
free_pvs() {
  local kc freed=0 name status
  kc=$(kubeconfig_local)
  while read -r name status; do
    [ -z "${name}" ] && continue
    case "${status}" in
      Released | Failed)
        KUBECONFIG="${kc}" "${HERE}/oc" patch pv "${name}" -p '{"spec":{"claimRef":null}}' >/dev/null 2>&1 || true
        freed=$((freed + 1))
        ;;
    esac
  done < <(KUBECONFIG="${kc}" "${HERE}/oc" get pv --no-headers 2>/dev/null | awk '/^sbx-pv/ {print $1, $5}')
  [ "${freed}" -gt 0 ] && ok "freed ${freed} released PV(s) back to Available"
  return 0
}

# `oc` against this cluster. The kubeconfig is resolved once per process rather than once per call —
# kubeconfig_local() rewrites the cluster stanza every time, and the verify stage below makes enough
# calls for that to be noise in the log.
OC_KUBECONFIG=""
OC() {
  [ -n "${OC_KUBECONFIG}" ] || OC_KUBECONFIG=$(kubeconfig_local)
  KUBECONFIG="${OC_KUBECONFIG}" "${HERE}/oc" "$@"
}

# =============================================================================
# kata — the sandboxed-containers operator and KataConfig
# =============================================================================
#
# This used to be a manual step out of REPRODUCE.md §3.6, run by hand after the script said it was
# finished. That is precisely the gap where "run it again and it works" stops being true: lesson 1.4.3
# hard-exits without a `kata` RuntimeClass, and its error message already promised this script
# installs one. It does now.
#
# The node used to REBOOT here, once, ~19 min: the operator's MachineConfig added the RHCOS
# extension, and an extension change means an MCO rollout. The extension is now a day-1 manifest
# (see ignition()), so the operator's MachineConfig matches what already exists and the MCO has
# nothing to do — minutes, no reboot. Every `oc` call in the wait is STILL allowed to fail, because
# if the operator ever generates a different MachineConfig than the day-1 replica, the reboot comes
# back, and an unreachable API mid-rollout must degrade the wait, not kill it.
kata() {
  local expect
  expect=$(stage_expect openshift-sno kata)

  # Idempotent by observation rather than by flag: if the RuntimeClass is already there and the
  # KataConfig reports a ready node, there is nothing to do and `--from kata` must be cheap.
  if [ -n "$(OC get runtimeclass kata --no-headers 2>/dev/null || true)" ] \
    && [ "$(OC get kataconfig cluster-kataconfig -o jsonpath='{.status.kataNodes.readyNodeCount}' 2>/dev/null || echo 0)" -ge 1 ] 2>/dev/null; then
    ok "runtimeclass kata already present and ready — nothing to do"
    return 0
  fi

  step "Installing the sandboxed-containers operator"
  OC apply -f "${HERE}/manifests/osc-operator.yaml" >/dev/null
  ok "Namespace + OperatorGroup + Subscription applied (channel: stable)"

  local csv="" phase="" last="" s
  # 90 x 10s = 15 min; measured at ~40 s on 2026-08-10
  for _ in $(seq 1 90); do
    csv=$(OC get csv -n openshift-sandboxed-containers-operator -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
    phase=$(OC get csv -n openshift-sandboxed-containers-operator -o jsonpath='{.items[0].status.phase}' 2>/dev/null || true)
    s="csv=${csv:-none} phase=${phase:-pending}"
    [ "${s}" != "${last}" ] && {
      echo "    [$(date +%H:%M:%S)] ${s}"
      last="${s}"
      hb_reset
    }
    [ "${phase}" = "Succeeded" ] && break
    hb "${expect}"
    sleep 10
  done
  [ "${phase}" = "Succeeded" ] || die "the sandboxed-containers CSV never reached Succeeded (last: ${s}).
       oc get sub,installplan,csv -n openshift-sandboxed-containers-operator"
  ok "operator ${csv} Succeeded"
  emit operator "sandboxed-containers operator installed" "csv=${csv}"

  step "Applying KataConfig (the extension is already on the node — expect minutes, not a reboot)"
  # Uptime before vs after is the honest reboot detector: a monotonically higher uptime across the
  # rollout proves no reboot happened, measured from inside rather than inferred from the day-1
  # manifest having been present.
  local up_before up_after
  up_before=$(node_ssh 'cut -d. -f1 /proc/uptime')
  # RETRY, and CHECK. The sandboxed-containers operator reports its CSV `Succeeded` before its
  # controller-manager has endpoints, so this apply can hit a validating webhook with nothing behind
  # it: `failed calling webhook "vkataconfig.kb.io": no endpoints available for service
  # "controller-manager-service"`. Measured 2026-08-15, and the controller was in CrashLoopBackOff at
  # the time for a second reason — it starts inside the metrics-server rollout window and dies on
  # `stale GroupVersion discovery: metrics.k8s.io/v1beta1`. Both clear on their own within a minute
  # or two, so the fix is to wait rather than to fail.
  #
  # The apply was previously unchecked, so a failed KataConfig left install.sh exiting **0** with no
  # Kata on the cluster — the worst kind of failure this repo has, a green light over a missing
  # boundary. Now it retries and then dies loudly.
  local applied=0
  for _ in $(seq 1 20); do
    if OC apply -f "${HERE}/manifests/kataconfig.yaml" >/dev/null 2>&1; then
      applied=1
      break
    fi
    sleep 15
  done
  [ "${applied}" -eq 1 ] || die "KataConfig could not be applied after 5 minutes.
       The usual cause is the operator's webhook having no endpoints yet — check:
         oc -n openshift-sandboxed-containers-operator get pods
       and re-run:  ./install.sh --from kata"
  local inprog ready total rc
  last=""
  # 120 x 30s = 60 min, the documented upper bound
  for _ in $(seq 1 120); do
    inprog=$(OC get kataconfig cluster-kataconfig -o jsonpath='{.status.conditions[?(@.type=="InProgress")].status}' 2>/dev/null || true)
    ready=$(OC get kataconfig cluster-kataconfig -o jsonpath='{.status.kataNodes.readyNodeCount}' 2>/dev/null || true)
    total=$(OC get kataconfig cluster-kataconfig -o jsonpath='{.status.kataNodes.nodeCount}' 2>/dev/null || true)
    # `|| true` is load-bearing, and this is the loop where its absence would actually bite. Under
    # `set -euo pipefail` a failing `oc` makes the pipeline non-zero, which makes the assignment
    # non-zero, which aborts the script — and an unreachable API is the EXPECTED path here, because
    # the KataConfig this loop is waiting on reboots the node out from under it. Same fault as
    # REPRODUCE.md §8's first entry, which killed two other wait loops on their success condition.
    rc=$(OC get runtimeclass kata --no-headers 2>/dev/null | wc -l | tr -d ' ' || true)
    s="InProgress=${inprog:-?} ready=${ready:-0}/${total:-0} runtimeclass=${rc:-0}"
    [ "${s}" != "${last}" ] && {
      echo "    [$(date +%H:%M:%S)] ${s}"
      last="${s}"
      hb_reset
    }
    # `runtimeclass kata` existing is necessary but NOT sufficient — the operator registers it before
    # the node has finished rebooting into the extension, and a pod scheduled in that window fails to
    # start with an error about a missing runtime handler. Wait for a READY node too.
    if [ "${rc:-0}" = "1" ] && [ "${ready:-0}" -ge 1 ] 2>/dev/null; then
      ok "runtimeclass kata registered, ${ready}/${total} node ready"
      up_after=$(node_ssh 'cut -d. -f1 /proc/uptime')
      if [ -n "${up_before}" ] && [ "${up_after:-0}" -gt "${up_before}" ] 2>/dev/null; then
        ok "no reboot: node uptime ${up_before}s -> ${up_after}s across the rollout (day-1 extension matched)"
      else
        # Not a failure — the cluster is correct either way — but it means the operator now
        # generates a different MachineConfig than manifests/day1-kata-extension.yaml replicates,
        # and the ~19-min day-2 reboot is back. Re-verify the replica against the operator source.
        ok "the node DID reboot (uptime ${up_before:-?}s -> ${up_after:-?}s) — day-1 extension no longer matches the operator's MachineConfig"
      fi
      emit kata "kata runtime ready" "ready=${ready}" "total=${total}"
      return 0
    fi
    hb "${expect}"
    sleep 30
  done
  die "KataConfig never became ready (last: ${s}).
       oc get kataconfig cluster-kataconfig -o yaml ; oc get mcp ; oc get nodes"
}

# =============================================================================
# openshell — the gateway lesson 1.4.4 drives
# =============================================================================
#
# Both blockers here were found on a live cluster and cost real time; neither is guessable from the
# chart's docs. They are recorded in tutorial/phase1-attacks/chapter-4-openshift/lesson-04-openshift-openshell/README.md and handled:
# Point the LOCAL openshell CLI at the in-cluster gateway, over a localhost port-forward.
#
# localhost deliberately. A NodePort would be simpler and would outlive this script — and it would
# also put an explicitly unauthenticated sandbox-creation API on a public IPv4 address.
#
# The CLI is the one in lesson 1.4.4's own venv, because it must be the version pinned against this
# chart: 0.0.101 was already current on PyPI while this chart was 0.0.99, and the two are released
# on separate cadences. `gateway add` is what seeds the gateway's config directory, so nothing else
# may touch that config first.
register_gateway() {
  local osh="${HERE}/../../tutorial/phase1-attacks/chapter-4-openshift/lesson-04-openshift-openshell/.venv/bin/openshell"
  if [ ! -x "${osh}" ]; then
    ok "openshell CLI not installed yet — run 'uv sync' in tutorial/phase1-attacks/chapter-4-openshift/lesson-04-openshift-openshell,
       then './install.sh --from openshell' to register the gateway"
    return 0
  fi
  "${HERE}/openshell-forward.sh" start
  OPENSHELL_DRIVERS=kubernetes OPENSHELL_GATEWAY=ocp \
    "${osh}" gateway add "http://127.0.0.1:18080" --name ocp >/dev/null 2>&1 || true
  OPENSHELL_DRIVERS=kubernetes OPENSHELL_GATEWAY=ocp \
    "${osh}" gateway select ocp >/dev/null 2>&1 || true
  # Down again: lesson 1.4.4's run.sh starts its own forward and takes it down on exit, so nothing is
  # left listening between runs.
  "${HERE}/openshell-forward.sh" stop >/dev/null 2>&1 || true
  ok "gateway registered with the local CLI as 'ocp'"
}

# the gateway's PVC needs the hostPath PVs from storage(), and those need the container_file_t
# relabel or the gateway CrashLoopBackOffs with a sqlite error that names neither hostPath nor
# SELinux. storage() runs before this stage for exactly that reason.
openshell() {
  local expect
  expect=$(stage_expect openshift-sno openshell)

  # The Agent Sandbox controller FIRST. Its CRD is what OpenShell's kubernetes driver creates objects
  # against, so a gateway installed without it comes up perfectly healthy and then fails every single
  # `sandbox create`. The asset is `sandbox.yaml`; guides written against v0.5.3 and earlier say
  # `manifests.yaml`, which no longer exists — a 404 that reads like a network problem.
  step "Installing the Agent Sandbox controller (v0.5.4)"
  OC apply --server-side -f \
    "https://github.com/kubernetes-sigs/agent-sandbox/releases/download/v0.5.4/sandbox.yaml" >/dev/null
  # POLL, do not `oc wait --for=condition=Established`. Between the apply returning and the API
  # populating the CRD's status there is a window where `.status.conditions` is nil, and `wait` does
  # not treat that as "not yet" — it dies with
  #     error: .status.conditions accessor error: <nil> is of the type <nil>, expected []interface{}
  # Measured on 2026-08-10. The k3s substrate gets away with the same line purely on timing.
  local established=""
  for _ in $(seq 1 60); do
    established=$(OC get crd sandboxes.agents.x-k8s.io \
      -o 'jsonpath={.status.conditions[?(@.type=="Established")].status}' 2>/dev/null || true)
    [ "${established}" = "True" ] && break
    sleep 3
  done
  [ "${established}" = "True" ] || die "the agent-sandbox CRD never became Established"
  ok "agent-sandbox CRD established"

  step "Installing the OpenShell gateway (chart 0.0.99, pinned — it is alpha)"
  OC get ns openshell >/dev/null 2>&1 || OC create ns openshell >/dev/null
  # THIS LINE IS LESSON 1.4.4'S SUBJECT, not setup noise: a policy sandbox that itself needs privileges
  # has to satisfy admission control before it can enforce anything, which is the collision between
  # this rung and lesson 1.4.2's SCC regime.
  OC adm policy add-scc-to-user privileged -z openshell-sandbox -n openshell >/dev/null
  ok "privileged SCC granted to serviceaccount openshell-sandbox in ns openshell"

  [ -n "${OC_KUBECONFIG}" ] || OC_KUBECONFIG=$(kubeconfig_local)
  KUBECONFIG="${OC_KUBECONFIG}" helm upgrade --install openshell \
    oci://ghcr.io/nvidia/openshell/helm-chart --version 0.0.99 -n openshell \
    --set server.disableTls=true \
    --set podSecurityContext.fsGroup=null \
    --set securityContext.runAsUser=null \
    --set server.auth.allowUnauthenticatedUsers=true >/dev/null
  ok "chart installed"

  local phase readyc last="" s
  # 60 x 10s = 10 min
  for _ in $(seq 1 60); do
    phase=$(OC -n openshell get pod openshell-0 -o jsonpath='{.status.phase}' 2>/dev/null || true)
    readyc=$(OC -n openshell get pod openshell-0 -o jsonpath='{.status.containerStatuses[0].ready}' 2>/dev/null || true)
    s="openshell-0 phase=${phase:-pending} ready=${readyc:-false}"
    [ "${s}" != "${last}" ] && {
      echo "    [$(date +%H:%M:%S)] ${s}"
      last="${s}"
      hb_reset
    }
    if [ "${phase}" = "Running" ] && [ "${readyc}" = "true" ]; then
      ok "gateway openshell-0 is 1/1 Running"
      register_gateway
      emit openshell "gateway ready"
      return 0
    fi
    hb "${expect}"
    sleep 10
  done
  die "the OpenShell gateway never became ready (last: ${s}).
       oc -n openshell get pod,pvc ; oc -n openshell logs openshell-0
       A PVC stuck Pending means storage() did not run; a sqlite 'unable to open database file'
       means the container_file_t relabel did not take."
}

# =============================================================================
# verify — is this cluster actually fit for lessons 1.4.1–1.4.4?
# =============================================================================
#
# Asserted FROM INSIDE, never from the flag we passed. A cluster that installed cleanly and cannot
# run a Kata pod looks identical to a working one until lesson 1.4.3 fails an hour later, on a box that
# bills the whole time. Every check here is one a lesson depends on.
verify() {
  local fails=0
  # shellcheck disable=SC2317  # invoked below; shellcheck cannot see through the loop
  vok() {
    echo "    [OK] $*"
    emit verify "$*" "result=pass"
    hb_reset
  }
  vbad() {
    echo "    [!!] $*" >&2
    emit verify "$*" "result=fail"
    fails=$((fails + 1))
    hb_reset
  }

  step "1/4 — the node and the operators"
  local node avail total
  # `|| true` for the same reason as in wait_api: `oc get nodes` exits non-zero on an empty cluster,
  # `pipefail` promotes that over `head`'s 0, and a failed substitution in an assignment trips
  # `set -e`. A VERIFIER that dies instead of reporting "node absent" is the worst version of this
  # bug — it turns a finding into a crash.
  node=$(OC get nodes --no-headers 2>/dev/null | awk '{print $2}' | head -1 || true)
  avail=$(OC get co --no-headers 2>/dev/null | awk '$3=="True"' | wc -l | tr -d ' ' || true)
  total=$(OC get co --no-headers 2>/dev/null | wc -l | tr -d ' ' || true)
  if [ "${node}" = "Ready" ]; then vok "node is Ready"; else vbad "node is '${node:-absent}', not Ready"; fi
  # All-but-the-*.apps-blocked is the designed steady state, not a tolerance: authentication (and
  # console, on a pre-trim cluster — the capability trim removes it entirely) cannot resolve *.apps
  # without the wildcard DNS this cluster deliberately skips (Trap #10).
  if [ "${total}" -gt 0 ] && [ "${avail}" -ge $((total - 3)) ]; then
    vok "${avail}/${total} cluster operators Available"
  else
    vbad "only ${avail}/${total} cluster operators Available"
  fi

  step "2/4 — Kata is a real VM (DMI, virtio and the resource gap; NEVER the kernel string)"
  OC -n default delete pod kata-verify --ignore-not-found --now >/dev/null 2>&1 || true
  local logs="" p
  if OC apply -f "${HERE}/manifests/kata-verify-pod.yaml" >/dev/null 2>&1; then
    for _ in $(seq 1 60); do
      p=$(OC -n default get pod kata-verify -o jsonpath='{.status.phase}' 2>/dev/null || true)
      case "${p}" in Succeeded | Failed | Running) break ;; esac
      hb 120
      sleep 5
    done
    logs=$(OC -n default logs kata-verify 2>/dev/null || true)
  fi
  if [ -z "${logs}" ]; then
    vbad "the kata-verify pod produced no output (phase=${p:-unknown})"
  else
    # shellcheck disable=SC2001  # per-LINE prefix of a multi-line string; ${x//} cannot do that
    echo "${logs}" | sed 's/^/        /'
    local dmi virtio nproc
    dmi=$(sed -n 's/^DMI_PRODUCT=//p' <<<"${logs}")
    virtio=$(sed -n 's/^VIRTIO_DEVS=//p' <<<"${logs}")
    nproc=$(sed -n 's/^NPROC=//p' <<<"${logs}")
    local nodecpu
    nodecpu=$(OC get node -o jsonpath='{.items[0].status.capacity.cpu}' 2>/dev/null || echo 0)
    case "${dmi}" in *KVM* | *kvm*) vok "DMI reports a hypervisor: ${dmi}" ;; *) vbad "DMI_PRODUCT='${dmi:-}' — this pod is NOT in a VM, Kata fell back to runc" ;; esac
    if [ "${virtio:-0}" -gt 0 ] 2>/dev/null; then
      vok "${virtio} virtio devices — they exist only inside a VM"
    else
      vbad "no virtio devices"
    fi
    if [ "${nproc:-0}" -gt 0 ] 2>/dev/null && [ "${nproc}" -lt "${nodecpu}" ] 2>/dev/null; then
      vok "guest has ${nproc} CPUs against the node's ${nodecpu}"
    else
      vbad "guest CPU count ${nproc:-?} does not differ from the node's ${nodecpu}"
    fi
  fi
  OC -n default delete pod kata-verify --ignore-not-found --now --wait=false >/dev/null 2>&1 || true

  step "3/4 — SCC admission refuses an over-privileged pod"
  OC delete ns scctest --ignore-not-found --wait=false >/dev/null 2>&1 || true
  OC create ns scctest >/dev/null 2>&1 || true
  OC -n scctest create sa rogue >/dev/null 2>&1 || true
  # `edit` first, or RBAC refuses before SCC is ever consulted and the demo proves nothing (Trap #13).
  OC -n scctest adm policy add-role-to-user edit system:serviceaccount:scctest:rogue >/dev/null 2>&1 || true
  local out rc2
  set +e
  out=$(OC -n scctest --as=system:serviceaccount:scctest:rogue create -f "${HERE}/manifests/priv-pod.yaml" 2>&1)
  rc2=$?
  set -e
  if [ "${rc2}" -ne 0 ] && grep -qi "security context constraint" <<<"${out}"; then
    vok "privileged pod refused by SCC admission"
  elif [ "${rc2}" -ne 0 ]; then
    vbad "privileged pod was refused, but not by SCC: ${out}"
  else
    vbad "privileged pod was ADMITTED — SCC is not enforcing"
  fi
  set +e
  out=$(OC -n scctest --as=system:serviceaccount:scctest:rogue create -f "${HERE}/manifests/compliant-pod.yaml" 2>&1)
  rc2=$?
  set -e
  if [ "${rc2}" -eq 0 ]; then
    vok "compliant pod admitted, scc=$(OC -n scctest get pod compliant -o jsonpath='{.metadata.annotations.openshift\.io/scc}' 2>/dev/null || echo '?')"
  else
    vbad "the compliant pod was rejected too — that is a broken cluster, not a policy: ${out}"
  fi
  OC delete ns scctest --ignore-not-found --wait=false >/dev/null 2>&1 || true

  step "4/4 — the OpenShell gateway"
  if [ "$(OC -n openshell get pod openshell-0 -o jsonpath='{.status.containerStatuses[0].ready}' 2>/dev/null || true)" = "true" ]; then
    vok "openshell-0 is 1/1 Running"
  else
    vbad "openshell-0 is not ready"
  fi

  if [ "${fails}" -eq 0 ]; then
    step "Cluster is fit for lessons 1.4.1–1.4.4."
  else
    die "${fails} verification check(s) FAILED — do not run lessons against this cluster.
       The box is still up. Investigate with ./install.sh --status, or destroy it with
       ../down.sh ${CLUSTER} (EUR $(hourly_price EM-B112X-SSD baremetal)/hr while it lives)."
  fi
}

cluster_status() {
  local kc
  kc=$(kubeconfig_local)
  step "Cluster status"
  KUBECONFIG="${kc}" "${HERE}/oc" get clusterversion 2>&1 | sed 's/^/    /' || true
  # Expected steady state: everything Available except the *.apps-blocked pair — authentication and
  # ingress stay Degraded because the wildcard DNS is deliberately skipped (Trap #10), and console
  # does not exist on a trimmed cluster. None of that blocks Kata or SCC.
  KUBECONFIG="${kc}" "${HERE}/oc" get co 2>/dev/null | awk 'NR==1||$3!="True"||$5=="True"' | sed 's/^/    /' || true
}

# Keep every run, and make it watchable. run_track tees stdout into the log below (a human still sees
# it happen, and the ANSI-vs-plain decision was already made above from the real tty, so the file
# stays greppable) AND opens the event stream every watcher reads. It no-ops under ctl.py, which has
# already made both files — hence the guard on the message rather than an unconditional echo.
start_run_log() {
  mkdir -p "${STATE_DIR}"
  run_track up "${CLUSTER}" "${STATE_DIR}/${CLUSTER}-$(date -u +%Y%m%dT%H%M%SZ).log"
  [ -z "${SBX_RUN_LOG}" ] || echo "==> logging this run to ${SBX_RUN_LOG/#$HOME/\~}"
}

main() {
  case "${1:-}" in
    --preflight)
      preflight
      exit 0
      ;;
    --facts)
      facts
      exit 0
      ;;
    --status)
      cluster_status
      exit 0
      ;;
    --storage)
      storage
      exit 0
      ;;
    --verify)
      verify
      exit 0
      ;;
    --from) shift ;;
    # No argument means the whole thing, which starts at the first stage in the manifest — named
    # there and not here, or `preflight` gets skipped by a default run the day it moves.
    "") ;;
    *) die "usage: ./install.sh [--preflight|--facts|--status|--storage|--verify|--from <stage>]" ;;
  esac
  # The stage ids are an interface: REPRODUCE.md documents `--from api` as the recovery move, ctl.py
  # passes them straight through, stages.json carries a measured duration for each, and every watcher
  # renders progress against that list. So the list is READ from stages.json rather than repeated
  # here. A hardcoded copy had already drifted: it omitted `preflight`, which cost nothing at run
  # time but made every watcher stick at 9/10 with a stage that could never start — and made
  # `--from preflight` match nothing, run zero stages, and print "Cluster is up and verified".
  local stages=() s
  while read -r s; do [ -z "${s}" ] || stages+=("${s}"); done < <(
    jq -r '."openshift-sno".stages[].id' "${STAGES_JSON}"
  )
  [ "${#stages[@]}" -gt 0 ] || die "stages.json lists no stages for openshift-sno"
  local from="${1:-${stages[0]}}"
  local started=0 known=""
  # A plain loop, not `printf | grep -qx`: with pipefail, grep -q closing the pipe early can leave
  # printf killed by SIGPIPE, and the check then rejects a perfectly good stage name now and then.
  for s in "${stages[@]}"; do
    if [ "${s}" = "${from}" ]; then known=1; fi
  done
  [ -n "${known}" ] || die "'${from}' is not a stage. Known: ${stages[*]}"
  start_run_log
  for s in "${stages[@]}"; do
    [ "${s}" = "${from}" ] && started=1
    [ "${started}" -eq 1 ] || continue
    # Centrally, rather than inside each function: a stage that forgets to close itself would leave
    # the watcher showing it as still running forever, and `die` reports failure against whatever
    # SBX_STAGE currently names.
    stage_begin "${s}" "$(jq -r --arg s "${s}" 'first(."openshift-sno".stages[] | select(.id == $s) | .title) // $s' "${STAGES_JSON}")"
    case "${s}" in
      # Its own stage, not a preamble folded into provision: it is the only one that costs nothing,
      # which is the whole design of preflight — find out for EUR 0, with no box running yet.
      preflight) preflight ;;
      provision) provision ;;
      facts) facts ;;
      ignition) ignition ;;
      kexec) kexec_live ;;
      api) wait_api ;;
      storage)
        storage
        cluster_status
        ;;
      kata) kata ;;
      openshell) openshell ;;
      verify) verify ;;
    esac
    stage_end ok
  done
  cat <<EOF

  Cluster is up and verified for lessons 1.4.1–1.4.4. Next:
    cd ../../tutorial/phase1-attacks/chapter-4-openshift/lesson-01-openshift-pod && ./run.sh
    ./install.sh --status                 cluster version + any degraded operators
    ../down.sh ${CLUSTER}                 DESTROY IT — EUR $(hourly_price EM-B112X-SSD baremetal)/hr while it lives

EOF
}

main "$@"
