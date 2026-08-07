#!/usr/bin/env bash
# Assert a lesson's boundary FROM INSIDE the sandbox, never from the flag that was passed.
#
#   ./check.sh lesson-03-container-gvisor
#
# Every check here answers "whose kernel replied?" rather than "did the command exit 0". A container
# that silently fell back to runc exits 0 and prints everything the lesson expects; the only thing
# that catches it is asking the sandbox itself what kernel it is running on. That is why each case
# below reads `uname -r` (or a device, or a policy decision) from inside a throwaway container and
# compares it against the node.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=lib.sh
source "${HERE}/lib.sh"

LESSON="${1:?usage: ./check.sh <lesson>}"
ALPINE=docker.io/library/alpine:3.22

pass() { echo "    [OK] $*"; }
fail() {
  echo "    [!!] $*" >&2
  FAILED=1
}
FAILED=0

NODE_KERNEL=$(box_ssh "${LESSON}" 'uname -r')
echo "    node kernel: ${NODE_KERNEL}"

for sub in $(lesson_substrates "${LESSON}"); do
  case "${sub}" in
    10-podman)
      got=$(box_ssh "${LESSON}" "podman run --rm --network none ${ALPINE} uname -r" 2>/dev/null || echo FAILED)
      if [ "${got}" = "${NODE_KERNEL}" ]; then
        pass "podman: container runs on the NODE kernel (${got}) — correct, a container is not a kernel boundary"
      else
        fail "podman: container kernel '${got}' != node '${NODE_KERNEL}' — something else is intercepting"
      fi
      ;;

    20-runsc)
      # Rootful, and that is not laziness: rootless podman cannot drive runsc at all. The systemd
      # cgroup manager gets "Interactive authentication required" from the system D-Bus, and the
      # cgroupfs manager cannot write /sys/fs/cgroup/cgroup.subtree_control. Lesson 3 runs rootful
      # for the same reason, on BOTH runtimes, so its one-variable comparison still holds.
      got=$(box_ssh "${LESSON}" "sudo podman run --rm --network none --runtime runsc ${ALPINE} uname -r" 2>/dev/null || echo FAILED)
      case "${got}" in
        *gvisor*) pass "gVisor: sandbox reports its OWN kernel (${got}), not the node's" ;;
        "${NODE_KERNEL}") fail "gVisor: sandbox reports the NODE kernel (${got}) — runsc did NOT engage, this is the silent fallback" ;;
        *) fail "gVisor: unexpected kernel '${got}'" ;;
      esac
      ;;

    30-containerd-kata)
      got=$(box_ssh "${LESSON}" "sudo nerdctl run --rm --net none --runtime io.containerd.kata.v2 ${ALPINE} uname -r" 2>/dev/null || echo FAILED)
      if [ "${got}" = "FAILED" ] || [ -z "${got}" ]; then
        fail "Kata: could not run a container under io.containerd.kata.v2"
      elif [ "${got}" = "${NODE_KERNEL}" ]; then
        fail "Kata: guest kernel == node kernel (${got}) — no VM was created, the shim fell back"
      else
        pass "Kata: guest kernel ${got} != node ${NODE_KERNEL} — a real VM booted"
      fi
      # Kernel string alone is not proof on RHEL-family hosts (Red Hat builds the guest kernel from
      # the same base). DMI is: a VM reports its hypervisor, metal reports its motherboard.
      dmi=$(box_ssh "${LESSON}" "sudo nerdctl run --rm --net none --runtime io.containerd.kata.v2 ${ALPINE} cat /sys/class/dmi/id/sys_vendor" 2>/dev/null || echo "?")
      echo "    kata guest DMI sys_vendor: ${dmi}"
      ;;

    40-openshell)
      # The substrate wrote what the CLI needs to a dedicated env file (NOT ~/.bashrc, which
      # Debian guards against non-interactive shells); source it exactly as `run.sh` does.
      #
      # Matched with `grep -q` on the PIPELINE rather than by counting. `grep -c` prints "0" and
      # exits 1 when it matches nothing, so the obvious `$(... | grep -c X || echo 0)` captures
      # "0\n0" — which is not equal to "0", and the check then reports a healthy gateway precisely
      # when the gateway is down. That is the exact failure this whole file exists to catch.
      # shellcheck disable=SC2016  # must expand on the box, not here
      if box_ssh "${LESSON}" 'source ~/.sandboxing-tutorial.env 2>/dev/null; openshell status 2>&1' | grep -q Connected; then
        pass "OpenShell: gateway reachable and Connected"
      else
        fail "OpenShell: gateway not Connected — see substrates/README.md, this is the private-IP constraint"
      fi
      ;;

    50-nat-vm)
      # Asked of the HOST, not of the guest. By the time this runs, up.sh has already re-pointed the
      # lesson at the guest, and the guest has no libvirt — so box_ssh here would always fail.
      got=$(box_ssh_host "${LESSON}" 'sudo virsh domstate openshell-guest 2>/dev/null' || echo "?")
      if [ "${got}" = "running" ]; then
        pass "NAT guest: libvirt domain 'openshell-guest' is running"
      else
        fail "NAT guest: domain state '${got}'"
      fi
      # The guest's whole reason to exist is a PRIVATE primary address on its default-route
      # interface. A public one there means OpenShell will refuse to start, so read it, don't assume.
      addr=$(box_ssh "${LESSON}" "ip -4 -o addr show scope global | head -1 | awk '{print \$4}'" 2>/dev/null || echo "?")
      case "${addr}" in
        10.* | 192.168.* | 172.1[6-9].* | 172.2[0-9].* | 172.3[01].*)
          pass "NAT guest: primary address ${addr} is private — the topology OpenShell requires"
          ;;
        *) fail "NAT guest: primary address '${addr}' is not private; OpenShell's gateway will refuse to start" ;;
      esac
      ;;
  esac
done

[ "${FAILED}" -eq 0 ] || die "boundary assertions FAILED for ${LESSON} — the box is not what the lesson claims."
