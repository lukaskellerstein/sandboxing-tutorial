#!/usr/bin/env bash
# Assert a lesson's boundary FROM INSIDE the sandbox, never from the flag that was passed.
#
#   ./check.sh 1.2.2
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
# Every assertion below interrogates a MACHINE, so resolve to the box up front and use only that.
# `./check.sh 1.3.2` and `./check.sh chapter-03-k8s` must prove the same things,
# because on a shared chapter they are the same node — and the substrate list they dispatch on
# belongs to the box, so a four-substrate cluster asserts all four boundaries whichever name you use.
BOX=$(lesson_box "${LESSON}")
ALPINE=docker.io/library/alpine:3.22
#: Chapter 3's pod image — the same agent image, side-loaded onto the node by 60-k8s.sh. NOT :latest,
#: for the reason images/agent/import-k3s.sh spells out.
AGENT_IMAGE=docker.io/sandboxing-tutorial/agent:v1

pass() { echo "    [OK] $*"; }
fail() {
  echo "    [!!] $*" >&2
  FAILED=1
}
FAILED=0

# --- which VMM booted? (both chapters) ---------------------------------------

#: Three readings, one container start: "<kernel> <pci-device-count> <rootfs-fstype>". Every start
#: here boots a VM and costs seconds, so they are taken together — and they have to come from the
#: SAME guest anyway to be about one sandbox.
#:
#: The PCI count is the field that matters, because the kernel string CANNOT tell QEMU from
#: Firecracker: both boot the identical guest kernel, and that identity is the finding lesson 1.2.3 and
#: 8 are built on rather than a weakness of this check. Firecracker boots `pci=off` and puts virtio
#: on MMIO; QEMU emulates a PCI host bridge. Measured: 10 devices under kata-qemu, 0 under kata-fc.
# shellcheck disable=SC2016  # must expand inside the guest, not here
GUEST_FACTS='echo $(uname -r) $(ls /sys/bus/pci/devices 2>/dev/null | wc -l) $(grep " / " /proc/mounts | head -1 | cut -d" " -f3)'

# Ask one Kata guest what it is running on, on the CHAPTER 2 rung (nerdctl over containerd). The
# runtime name is the only parameter that varies, which is exactly the comparison substrate 35
# exists to make. Chapter 3 asks the same question of a Pod, through k8s_pod_output below.
kata_guest_facts() {
  local box="$1" runtime="$2" snapshotter="${3:-}" flags=""
  [ -n "${snapshotter}" ] && flags="--snapshotter ${snapshotter}"
  box_ssh "${box}" "sudo nerdctl run --rm --net none ${flags} --runtime ${runtime} \
    --entrypoint sh ${ALPINE} -c '${GUEST_FACTS}'" 2>/dev/null | tail -1
}

# --- chapter 3 helpers -------------------------------------------------------

# Run one throwaway pod and return what it printed. The runtime class is the ONLY thing that varies
# between lessons 1.3.1, 1.3.2 and 1.3.3, which is the chapter's whole argument — so it is the only parameter.
#
# `--command` overrides the image's ENTRYPOINT (which would otherwise run the attack suite), and
# --image-pull-policy=IfNotPresent keeps the kubelet off Docker Hub for an image already on the node.
#
# Create → poll for a terminal phase → read the logs → delete, rather than the far shorter
# `kubectl run --rm -i`. That shorter form is NOT deterministic: with `-i` kubectl attaches to the
# container, and when the container has already written its output and exited before the attach
# lands, kubectl also falls back to dumping the logs — so the reading comes back TWICE. It is a
# race, so it passes most of the time: one run here reported a clean `6.8.0-106-generic` and the
# next reported `6.8.0-106-generic\n6.8.0-106-generic`, which then failed to equal the node's kernel
# and read as "something is already intercepting". A check that is wrong intermittently is worse
# than one that is wrong always, because the passing runs teach you to trust it.
k8s_pod_output() {
  local lesson="$1" name="$2" rtclass="$3" out
  shift 3
  local overrides="{}"
  [ -n "${rtclass}" ] && overrides="{\"spec\":{\"runtimeClassName\":\"${rtclass}\"}}"
  out=$(box_ssh "${lesson}" "
    kubectl delete pod ${name} --ignore-not-found --now >/dev/null 2>&1
    kubectl run ${name} --restart=Never --quiet \
      --image=${AGENT_IMAGE} --image-pull-policy=IfNotPresent \
      --overrides='${overrides}' --command -- $* >/dev/null 2>&1
    for _ in \$(seq 1 90); do
      case \"\$(kubectl get pod ${name} -o jsonpath='{.status.phase}' 2>/dev/null)\" in
        Succeeded | Failed) break ;;
      esac
      sleep 2
    done
    kubectl logs ${name} 2>/dev/null
    kubectl delete pod ${name} --ignore-not-found --now --wait=false >/dev/null 2>&1
  " 2>/dev/null | tail -1)
  echo "${out:-FAILED}"
}

# One HTTP status from inside the probe pod, and ALWAYS exactly one token.
#
# The obvious spelling — `status=$(box_ssh ... curl ... || echo 000)` — is broken in the precise way
# this repo keeps re-learning. When egress is denied, `curl -w %{http_code}` prints "000" AND exits
# non-zero, so the `|| echo 000` fires too and the capture is "000\n000". That is not equal to "000",
# so the caller concludes the policy did NOT engage at exactly the moment it did — the same shape as
# the `grep -c` bug documented further down this file. `tail -1` collapses it to one value, and the
# `:-000` covers the case where nothing was printed at all.
k8s_curl_status() {
  local out
  out=$(box_ssh "$1" "kubectl -n $2 exec np-probe -- curl -sS -m 5 -o /dev/null -w %{http_code} https://1.1.1.1 2>/dev/null" 2>/dev/null | tail -1)
  echo "${out:-000}"
}

# Prove a NetworkPolicy is ENFORCED, with packets rather than with `kubectl get netpol`.
#
# This is the single most important assertion in chapter 3. k3s's default CNI is flannel, which does
# not implement NetworkPolicy at all; enforcement comes from a controller k3s embeds alongside it. On
# a cluster where that controller is off, every NetworkPolicy object is still accepted, still listed,
# and still completely ignored — so lesson 1.3.1 would report a scoreboard full of BLOCKED rows for
# attacks that in fact walked straight out of the pod.
#
# Both halves are required, and the order is why. A pod that cannot reach the internet for some
# unrelated reason (no default route, a broken CNI, DNS) would make the deny-all half "pass" while
# proving nothing whatsoever. So: reachable WITHOUT the policy, unreachable WITH it. Either half
# alone is worthless.
k8s_netpol_enforced() {
  local lesson="$1" ns=sbx-netpol-check
  local before after waited=0

  # ONE long-lived pod, probed with `kubectl exec`, rather than a fresh pod per measurement.
  #
  # The obvious version — run a pod whose command is the curl — measures the wrong thing and fails.
  # A NetworkPolicy is not a property of the cluster, it is rules a controller writes when it sees a
  # pod; that controller reacts to the pod's CREATION, so for the first seconds of a pod's life the
  # rules for it do not exist yet. A container that curls on its first instruction beats the
  # controller to it and reports the policy unenforced, every time. (Measured: a one-shot pod got the
  # same 301 with and without a deny-all policy.)
  #
  # Exec'ing into an already-running pod removes that race from the measurement, and the retry loop
  # below then reports how long enforcement actually took to land — which is a real property worth
  # knowing rather than an inconvenience to hide.
  box_ssh "${lesson}" "kubectl create namespace ${ns} --dry-run=client -o yaml | kubectl apply -f - >/dev/null"
  box_ssh "${lesson}" "kubectl -n ${ns} run np-probe --restart=Never --quiet \
      --image=${AGENT_IMAGE} --image-pull-policy=IfNotPresent --command -- sleep 600 >/dev/null 2>&1" || true
  box_ssh "${lesson}" "kubectl -n ${ns} wait --for=condition=Ready pod/np-probe --timeout=180s >/dev/null" || true

  before=$(k8s_curl_status "${lesson}" "${ns}")

  box_ssh "${lesson}" "kubectl -n ${ns} apply -f - >/dev/null <<'YAML'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-egress
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress: []
YAML"

  after="${before}"
  for _ in $(seq 1 20); do
    after=$(k8s_curl_status "${lesson}" "${ns}")
    [ "${after}" = "000" ] && break
    waited=$((waited + 3))
    sleep 3
  done

  box_ssh "${lesson}" "kubectl delete namespace ${ns} --wait=false >/dev/null 2>&1" || true

  echo "    netpol probe: without policy -> ${before:-?}, with deny-all -> ${after:-?} (after ${waited}s)"
  if [ "${before}" = "000" ] || [ -z "${before}" ]; then
    fail "NetworkPolicy: the pod could NOT reach the internet even with no policy — the control is untested, not proven"
  elif [ "${after}" != "000" ]; then
    fail "NetworkPolicy: deny-all egress was ACCEPTED BUT NOT ENFORCED after ${waited}s (still ${after}) — lesson 1.3.1's scoreboard would be a lie"
  else
    pass "NetworkPolicy is enforced (took ${waited}s to take effect): ${before} without it, no route with it"
  fi
}

NODE_KERNEL=$(box_ssh "${BOX}" 'uname -r')
echo "    node kernel: ${NODE_KERNEL}"

for sub in $(lesson_substrates "${BOX}"); do
  # Substrates are named by chapter now (`chapter-3/60-k8s`), because chapter 3's four all land on
  # one shared cluster and the grouping is what makes that set legible. Match on the BASENAME so
  # every arm below stays the plain substrate name: the chapter a script lives in is a fact about
  # the tree, never about what the assertion has to prove.
  case "${sub##*/}" in
    10-podman)
      got=$(box_ssh "${BOX}" "podman run --rm --network none ${ALPINE} uname -r" 2>/dev/null || echo FAILED)
      if [ "${got}" = "${NODE_KERNEL}" ]; then
        pass "podman: container runs on the NODE kernel (${got}) — correct, a container is not a kernel boundary"
      else
        fail "podman: container kernel '${got}' != node '${NODE_KERNEL}' — something else is intercepting"
      fi
      ;;

    20-runsc)
      # Rootful, and that is not laziness: rootless podman cannot drive runsc at all. The systemd
      # cgroup manager gets "Interactive authentication required" from the system D-Bus, and the
      # cgroupfs manager cannot write /sys/fs/cgroup/cgroup.subtree_control. Lesson 1.2.2 runs rootful
      # for the same reason, on BOTH runtimes, so its one-variable comparison still holds.
      got=$(box_ssh "${BOX}" "sudo podman run --rm --network none --runtime runsc ${ALPINE} uname -r" 2>/dev/null || echo FAILED)
      case "${got}" in
        *gvisor*) pass "gVisor: sandbox reports its OWN kernel (${got}), not the node's" ;;
        "${NODE_KERNEL}") fail "gVisor: sandbox reports the NODE kernel (${got}) — runsc did NOT engage, this is the silent fallback" ;;
        *) fail "gVisor: unexpected kernel '${got}'" ;;
      esac
      ;;

    30-containerd-kata)
      got=$(box_ssh "${BOX}" "sudo nerdctl run --rm --net none --runtime io.containerd.kata.v2 ${ALPINE} uname -r" 2>/dev/null || echo FAILED)
      if [ "${got}" = "FAILED" ] || [ -z "${got}" ]; then
        fail "Kata: could not run a container under io.containerd.kata.v2"
      elif [ "${got}" = "${NODE_KERNEL}" ]; then
        fail "Kata: guest kernel == node kernel (${got}) — no VM was created, the shim fell back"
      else
        pass "Kata: guest kernel ${got} != node ${NODE_KERNEL} — a real VM booted"
      fi
      # Kernel string alone is not proof on RHEL-family hosts (Red Hat builds the guest kernel from
      # the same base). DMI is: a VM reports its hypervisor, metal reports its motherboard.
      dmi=$(box_ssh "${BOX}" "sudo nerdctl run --rm --net none --runtime io.containerd.kata.v2 ${ALPINE} cat /sys/class/dmi/id/sys_vendor" 2>/dev/null || echo "?")
      echo "    kata guest DMI sys_vendor: ${dmi}"
      ;;

    35-containerd-devmapper)
      # A SECOND hypervisor under the same runtime, so the question is no longer "did a VM boot" —
      # case 30 settled that — but "WHICH VMM booted". The kernel string cannot answer it: both
      # hypervisors boot the identical guest kernel, which is the finding lesson 1.2.3 is built on.
      #
      # /sys/bus/pci/devices does answer it. Firecracker has no PCI bus at all (`pci=off` is on its
      # kernel command line) and puts virtio on MMIO instead; QEMU emulates a PCI host bridge and
      # hangs virtio off it. Measured on this box: 10 devices under kata-qemu, 0 under kata-fc.
      #
      # Both are asserted, not just the new one. This substrate makes the Firecracker config the
      # second of Kata's two shipped config slots, and the shim falls back to the first when nothing
      # names one — so "did kata-qemu quietly become Firecracker" is a real question here, and a
      # silent hypervisor swap would leave every kata-qemu number in the tutorial wrong.
      read -r q_kernel q_pci q_rootfs <<<"$(kata_guest_facts "${BOX}" io.containerd.kata.v2)"
      read -r f_kernel f_pci f_rootfs <<<"$(kata_guest_facts "${BOX}" io.containerd.kata-fc.v2 devmapper)"
      echo "    kata-qemu: kernel=${q_kernel:-?} pci=${q_pci:-?} rootfs=${q_rootfs:-?}"
      echo "    kata-fc  : kernel=${f_kernel:-?} pci=${f_pci:-?} rootfs=${f_rootfs:-?}"

      if [ -z "${f_kernel}" ] || [ "${f_kernel}" = "FAILED" ]; then
        fail "Firecracker: could not run a container under io.containerd.kata-fc.v2 — is the thin-pool up?"
      elif [ "${f_kernel}" = "${NODE_KERNEL}" ]; then
        fail "Firecracker: guest kernel == node kernel (${f_kernel}) — no VM was created, the shim fell back"
      elif [ "${f_pci}" != "0" ]; then
        fail "Firecracker: the guest has ${f_pci} PCI devices — Firecracker has no PCI bus, so this is QEMU wearing the kata-fc runtime name"
      else
        pass "Firecracker: guest kernel ${f_kernel}, and NO PCI bus (${f_pci} devices) — virtio over MMIO, so this really is Firecracker"
      fi

      # The rootfs type is the devmapper requirement seen from the inside: Firecracker has no
      # virtio-fs to share a directory in with, so the rootfs arrives as a block device instead.
      case "${f_rootfs}" in
        ext4) pass "Firecracker: rootfs is a block device (${f_rootfs}) — what the devmapper snapshotter is for" ;;
        virtiofs) fail "Firecracker: rootfs is ${f_rootfs} — a shared FS, which Firecracker cannot do; this is not Firecracker" ;;
        *) echo "    Firecracker rootfs '${f_rootfs}' — unexpected, but the PCI row above is the proof" ;;
      esac

      if [ "${q_pci}" = "0" ]; then
        fail "kata-qemu has NO PCI bus — it is running Firecracker, and every kata-qemu measurement on this box is wrong"
      elif [ -n "${q_pci}" ] && [ "${q_pci}" != "?" ]; then
        pass "kata-qemu still gets QEMU (${q_pci} PCI devices, rootfs ${q_rootfs}) — the two hypervisors coexist"
      else
        fail "kata-qemu: could not read the guest at all"
      fi
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
      if box_ssh "${BOX}" 'source ~/.sandboxing-tutorial.env 2>/dev/null; openshell status 2>&1' | grep -q Connected; then
        pass "OpenShell: gateway reachable and Connected"
      else
        fail "OpenShell: gateway not Connected — see substrates/README.md, this is the private-IP constraint"
      fi
      ;;

    50-nat-vm)
      # Asked of the HOST, not of the guest. By the time this runs, up.sh has already re-pointed the
      # lesson at the guest, and the guest has no libvirt — so box_ssh here would always fail.
      got=$(box_ssh_host "${BOX}" 'sudo virsh domstate openshell-guest 2>/dev/null' || echo "?")
      if [ "${got}" = "running" ]; then
        pass "NAT guest: libvirt domain 'openshell-guest' is running"
      else
        fail "NAT guest: domain state '${got}'"
      fi
      # The guest's whole reason to exist is a PRIVATE primary address on its default-route
      # interface. A public one there means OpenShell will refuse to start, so read it, don't assume.
      addr=$(box_ssh "${BOX}" "ip -4 -o addr show scope global | head -1 | awk '{print \$4}'" 2>/dev/null || echo "?")
      case "${addr}" in
        10.* | 192.168.* | 172.1[6-9].* | 172.2[0-9].* | 172.3[01].*)
          pass "NAT guest: primary address ${addr} is private — the topology OpenShell requires"
          ;;
        *) fail "NAT guest: primary address '${addr}' is not private; OpenShell's gateway will refuse to start" ;;
      esac
      ;;

    60-k8s)
      ready=$(box_ssh "${BOX}" "kubectl get nodes --no-headers 2>/dev/null | awk '{print \$2}'" || echo "?")
      if [ "${ready}" = "Ready" ]; then
        pass "k3s: the node is Ready"
      else
        fail "k3s: node status '${ready}' — the cluster is not usable"
      fi

      # The EXPECTED answer here is "identical", and it is the whole of lesson 6. A pod composes
      # namespaces and cgroups exactly as lesson 1.2.1's container did; it is not a kernel boundary, and
      # a reader has to see that stated by the machine before lessons 1.3.2 and 1.3.3 mean anything.
      got=$(k8s_pod_output "${BOX}" sbxchk-kernel "" uname -r)
      if [ "${got}" = "${NODE_KERNEL}" ]; then
        pass "pod runs on the NODE kernel (${got}) — correct, a pod is not a kernel boundary"
      else
        fail "pod kernel '${got}' != node '${NODE_KERNEL}' — something is already intercepting, and lesson 1.3.1's baseline is wrong"
      fi

      k8s_netpol_enforced "${BOX}"
      ;;

    70-k8s-gvisor)
      got=$(k8s_pod_output "${BOX}" sbxchk-gvisor gvisor uname -r)
      case "${got}" in
        *gvisor*) pass "gVisor pod reports its OWN kernel (${got}), not the node's" ;;
        "${NODE_KERNEL}") fail "gVisor pod reports the NODE kernel (${got}) — the RuntimeClass was accepted and runc ran anyway, the silent fallback" ;;
        *) fail "gVisor pod: unexpected kernel '${got}'" ;;
      esac
      ;;

    75-k8s-devmapper)
      # Only the snapshotter, because that is all this substrate installs. Whether a Firecracker POD
      # runs is asserted in the 80-k8s-kata case below, which is where both halves exist.
      #
      # `ok` is the only state that licenses a claim here. `skip` means containerd loaded the plugin
      # and declined to configure it, and it is invisible until a kata-fc pod fails minutes later at
      # sandbox creation — a failure that reads like a broken Kata install and is a missing pool.
      state=$(box_ssh "${BOX}" "sudo k3s ctr plugins ls | awk '\$2 == \"devmapper\" {print \$4}'" 2>/dev/null | tail -1)
      if [ "${state}" = "ok" ]; then
        pass "devmapper snapshotter is ${state} — Firecracker has somewhere to put a block rootfs"
      else
        fail "devmapper snapshotter is '${state:-absent}', not ok — every kata-fc pod will fail at sandbox creation"
      fi
      ;;

    80-k8s-kata)
      # READ the class name; never guess it. kata-deploy registers one per enabled shim and the set
      # moves between releases — a hardcoded name here fails as "RuntimeClass not found" and reads
      # like a broken install rather than a stale assumption. On this cluster it registers 20+.
      #
      # Prefer kata-qemu, with the SAME precedence the substrate and the lesson use. Taking whichever
      # sorts first would be a real hole rather than a cosmetic one: `kata-clh` sorts ahead of
      # `kata-qemu`, so a box where clh worked and qemu did not would pass this check and then fail
      # the lesson. A setup assertion has to test the thing the lesson actually runs.
      kclass=$(box_ssh "${BOX}" \
        "kubectl get runtimeclass -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | grep -x 'kata-qemu' \
         || kubectl get runtimeclass -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | grep '^kata' | head -1" 2>/dev/null || echo "")
      if [ -z "${kclass}" ]; then
        fail "Kata: no kata* RuntimeClass exists — kata-deploy did not register one"
      else
        echo "    kata RuntimeClass: ${kclass}"
        got=$(k8s_pod_output "${BOX}" sbxchk-kata "${kclass}" uname -r)
        if [ "${got}" = "FAILED" ] || [ -z "${got}" ]; then
          fail "Kata: could not run a pod under runtimeClassName ${kclass}"
        elif [ "${got}" = "${NODE_KERNEL}" ]; then
          fail "Kata: guest kernel == node kernel (${got}) — no VM was created, the shim fell back"
        else
          pass "Kata: guest kernel ${got} != node ${NODE_KERNEL} — a real VM booted"
        fi
        # INFORMATIONAL, and deliberately not gated on. DMI is the fallback witness for hosts where
        # the guest kernel legitimately MATCHES the node's — Red Hat builds Kata's guest kernel from
        # the same RHEL base, which is how chapter 4 confirmed a real VM on OpenShift (sys_vendor=KVM).
        # It is not available everywhere: measured here, neither kata-clh nor kata-qemu exposes
        # /sys/class/dmi at all, because a minimal guest need not build SMBIOS support in. The kernel
        # comparison above already settled it, so an absent DMI is a fact to print, not a failure.
        dmi=$(k8s_pod_output "${BOX}" sbxchk-kata-dmi "${kclass}" cat /sys/class/dmi/id/sys_vendor)
        echo "    kata guest DMI sys_vendor: ${dmi} (absent on a minimal guest — the kernel row is the proof)"
      fi

      # --- the SECOND hypervisor, if this node carries the storage for it ------
      #
      # kata-deploy registers `kata-fc` on every cluster it touches, so its mere presence in the list
      # proves nothing at all — without the devmapper snapshotter it is a class that always fails.
      # Assert it only where substrate 75 put that snapshotter there, and read the name from the
      # cluster with the same precedence discipline the qemu block above uses.
      if lesson_substrates "${BOX}" | grep -q '75-k8s-devmapper'; then
        fclass=$(box_ssh "${BOX}" \
          "kubectl get runtimeclass -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | grep -x 'kata-fc' \
           || kubectl get runtimeclass -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | grep '^kata-fc' | head -1" 2>/dev/null || echo "")
        if [ -z "${fclass}" ]; then
          fail "Firecracker: no kata-fc RuntimeClass exists — kata-deploy registered no Firecracker shim"
        else
          echo "    firecracker RuntimeClass: ${fclass}"
          # Both facts from ONE pod: each start boots a VM, and they have to describe the same guest.
          read -r fk fpci frootfs <<<"$(k8s_pod_output "${BOX}" sbxchk-kata-fc "${fclass}" sh -c "'${GUEST_FACTS}'")"
          echo "    kata-fc: kernel=${fk:-?} pci=${fpci:-?} rootfs=${frootfs:-?}"
          if [ -z "${fk}" ] || [ "${fk}" = "FAILED" ]; then
            fail "Firecracker: no pod would run under runtimeClassName ${fclass} — is the devmapper pool up?"
          elif [ "${fk}" = "${NODE_KERNEL}" ]; then
            fail "Firecracker: guest kernel == node kernel (${fk}) — no VM was created, the shim fell back"
          elif [ "${fpci}" != "0" ]; then
            # The kernel string cannot separate the two hypervisors — both boot the same guest kernel,
            # which is lesson 1.3.3's finding rather than a gap here. The PCI bus can: Firecracker boots
            # `pci=off` and puts virtio on MMIO, QEMU emulates a PCI host bridge.
            fail "Firecracker: the guest has ${fpci} PCI devices — Firecracker has no PCI bus, so this is QEMU under the kata-fc name"
          else
            pass "Firecracker: guest kernel ${fk}, and NO PCI bus (${fpci} devices) — a different VMM, not just a different name"
          fi
        fi
      fi
      ;;

    90-k8s-openshell)
      # grep -q on the PIPELINE, never `grep -c`: `grep -c` prints "0" AND exits 1 when it matches
      # nothing, so `$(... | grep -c X || echo 0)` captures "0\n0" — which is not "0", and the check
      # then reports a healthy gateway precisely when the gateway is down.
      # shellcheck disable=SC2016  # must expand on the box, not here
      if box_ssh "${BOX}" 'source ~/.sandboxing-tutorial.env 2>/dev/null; openshell status 2>&1' | grep -q Connected; then
        pass "OpenShell: gateway reachable and Connected"
      else
        fail "OpenShell: gateway not Connected — see substrates/README.md"
      fi
      crd=$(box_ssh "${BOX}" "kubectl get crd sandboxes.agents.x-k8s.io -o name 2>/dev/null" || echo "")
      if [ -n "${crd}" ]; then
        pass "Agent Sandbox CRD installed (${crd})"
      else
        fail "Agent Sandbox CRD missing — OpenShell's kubernetes driver has nothing to create objects against"
      fi
      ;;

    10-auditd)
      # The phase-2 host sensor. Assert it is RUNNING and its keyed rules are loaded — a lesson that
      # reads an empty trail would report "nothing was recorded" when the truth is "nothing was
      # watching", the audit-side twin of this repo's silent-fallback failure.
      active=$(box_ssh "${BOX}" "systemctl is-active auditd 2>/dev/null || echo inactive" 2>/dev/null | tail -1)
      rules=$(box_ssh "${BOX}" "sudo auditctl -l 2>/dev/null | grep -c sbx_" 2>/dev/null | tail -1)
      if [ "${active}" = "active" ] && [ "${rules:-0}" -gt 0 ]; then
        pass "auditd: active with ${rules} sandboxing rules loaded — the host sensor is watching"
      else
        fail "auditd: active='${active}' rules='${rules:-0}' — the sensor is not watching, 2.1.1's trail would be a false blank"
      fi
      ;;

    tetragon)
      # Assert the host sensor END TO END, not that a binary exists: start Tetragon with the lesson's
      # own policy, trigger one fingerprint FROM INSIDE A CONTAINER, and read it back out of the
      # export file. A policy that never compiles, a kprobe that never attaches, or a symbol this
      # kernel does not carry would all leave 2.2.1's trail empty — and an empty trail reads exactly
      # like "the container hid everything", which is this repo's characteristic false blank.
      #
      # The trigger is ALPINE on purpose. alpine is musl, which calls the `open` syscall where glibc
      # calls `openat`; a policy hooking only one passes a glibc trigger and then silently records
      # nothing for the other libc. Measured 2026-08-15 — this is how the sys_open gap was found.
      #
      # The second number is the discovery gate the whole per-probe mapping rests on: can an event be
      # ATTRIBUTED to the workload? NOT via `process.docker` — measured 2026-08-15, under rootless
      # podman that id lands on the host-side podman/crun/conmon and NOT on the container's own
      # process, so gating on it would credit the workload with the runtime's execs while missing
      # everything it actually did. The attribution is the process's own pid namespace, which the
      # kernel cannot be talked out of, and which needs --enable-process-ns to be exported.
      #
      # ON A CLUSTER the trigger is a POD and the attribution is by CONTAINER ID, not by pid
      # namespace. Both halves matter. A pid-namespace test cannot tell the attack pod from the
      # gateway pod running beside it, and every 2.3.x leaf has both alive at once — so a check that
      # only proved "some container" would bless a mapping that credits the wrong workload. The
      # container id is available here and was not in chapter 2: `process.docker` comes from the
      # cgroup, which rootless podman left empty and the kubelet fills in.
      #
      # What is deliberately NOT asserted is Tetragon's own `--enable-k8s-api` pod enrichment. It
      # does not resolve pods on this box and it delays every event up to 30 s — the full measurement
      # is in substrates/chapter-3-audit/tetragon.sh. This arm asserts the configuration we ship.
      ver="${TETRAGON_VERSION_NOTE:-v1.7.0 (pinned; the binary has no --version flag)}"
      if lesson_substrates "${BOX}" | grep -q '60-k8s'; then
        got=$(box_ssh "${BOX}" "sudo rm -f /tmp/sbx-check.jsonl; \
          sudo nohup tetragon --bpf-lib /usr/local/lib/tetragon/bpf --enable-process-ns --tracing-policy /etc/tetragon/sbx-sandboxing.yaml --export-filename /tmp/sbx-check.jsonl >/tmp/sbx-check.log 2>&1 & \
          sleep 20; \
          kubectl delete pod sbxchk-tetra --ignore-not-found --now >/dev/null 2>&1; \
          kubectl run sbxchk-tetra --restart=Never --quiet --image=${AGENT_IMAGE} --image-pull-policy=IfNotPresent \
            --command -- /bin/sh -c 'cat \$HOME/.ssh/id_rsa; true' >/dev/null 2>&1; \
          for _ in \$(seq 1 90); do
            case \"\$(kubectl get pod sbxchk-tetra -o jsonpath='{.status.phase}' 2>/dev/null)\" in
              Succeeded | Failed) break ;;
            esac
            sleep 2
          done
          cid=\$(kubectl get pod sbxchk-tetra -o jsonpath='{.status.containerStatuses[0].containerID}' 2>/dev/null); \
          sleep 5; sudo pkill -x tetragon >/dev/null 2>&1; sleep 2; \
          kubectl delete pod sbxchk-tetra --ignore-not-found --now --wait=false >/dev/null 2>&1; \
          sudo cat /tmp/sbx-check.jsonl 2>/dev/null | CID=\"\${cid}\" python3 -c \"
import sys, json, os
cid = os.environ.get('CID', '').split('://')[-1]
hits = inctr = 0
for line in sys.stdin:
    try:
        ev = json.loads(line)
    except ValueError:
        continue
    kp = ev.get('process_kprobe')
    if not isinstance(kp, dict):
        continue
    if 'sbx_probe=read_credentials' not in [*kp.get('tags', []), kp.get('message', '')]:
        continue
    hits += 1
    docker = str((kp.get('process') or {}).get('docker') or '')
    if cid and docker and cid.startswith(docker):
        inctr += 1
print('hits=%d inctr=%d' % (hits, inctr))
\"" 2>/dev/null | tail -1)
        echo "    tetragon probe (pod): ${got}   (policy /etc/tetragon/sbx-sandboxing.yaml)"
        hits=$(echo "${got}" | sed -n 's/.*hits=\([0-9]*\).*/\1/p')
        inctr=$(echo "${got}" | sed -n 's/.*inctr=\([0-9]*\).*/\1/p')
        if [ "${hits:-0}" -gt 0 ] && [ "${inctr:-0}" -gt 0 ]; then
          pass "Tetragon ${ver}: policy loads, and a kprobe fired inside a POD whose container id the cluster confirms — the host sensor sees through the pod, and its events can be attributed to one named workload"
        else
          fail "Tetragon ${ver}: ${got:-no output} — the sensor is not usable (hits=0: tetragon died, or the policy or a kprobe is dead; inctr=0: events arrive but carry no container id, so the per-POD mapping cannot tell the attack pod from the gateway beside it)"
        fi
        continue
      fi
      got=$(box_ssh "${BOX}" "sudo rm -f /tmp/sbx-check.jsonl; \
        sudo nohup tetragon --bpf-lib /usr/local/lib/tetragon/bpf --enable-process-ns --tracing-policy /etc/tetragon/sbx-sandboxing.yaml --export-filename /tmp/sbx-check.jsonl >/tmp/sbx-check.log 2>&1 & \
        sleep 20; mkdir -p /tmp/sbxc && printf x >/tmp/sbxc/.env; \
        podman run --rm -v /tmp/sbxc:/c:ro ${ALPINE} cat /c/.env >/dev/null 2>&1; \
        sleep 4; sudo pkill -x tetragon >/dev/null 2>&1; sleep 2; \
        sudo cat /tmp/sbx-check.jsonl 2>/dev/null | python3 -c \"
import sys, json
hits = inctr = 0
for line in sys.stdin:
    try:
        ev = json.loads(line)
    except ValueError:
        continue
    kp = ev.get('process_kprobe')
    if not isinstance(kp, dict):
        continue
    if 'sbx_probe=read_credentials' not in [*kp.get('tags', []), kp.get('message', '')]:
        continue
    hits += 1
    ns = (kp.get('process', {}).get('ns') or {}).get('pid')
    if isinstance(ns, dict) and not ns.get('is_host', False):
        inctr += 1
print('hits=%d inctr=%d' % (hits, inctr))
\"" 2>/dev/null | tail -1)
      echo "    tetragon probe: ${got}   (policy /etc/tetragon/sbx-sandboxing.yaml)"
      hits=$(echo "${got}" | sed -n 's/.*hits=\([0-9]*\).*/\1/p')
      inctr=$(echo "${got}" | sed -n 's/.*inctr=\([0-9]*\).*/\1/p')
      if [ "${hits:-0}" -gt 0 ] && [ "${inctr:-0}" -gt 0 ]; then
        pass "Tetragon ${ver}: policy loads, and a kprobe fired from inside a container's OWN pid namespace — the host sensor is watching, and its events can be attributed to the workload"
      else
        fail "Tetragon ${ver}: ${got:-no output} — the sensor is not usable (hits=0: the policy or a kprobe is dead, or this libc uses the syscall we did not hook; inctr=0: events arrive but carry no pid namespace, so the per-probe mapping cannot tell the workload from the box)"
      fi
      ;;

    72-k8s-gvisor-trace)
      # Two things, and the second is the one that matters. A pod under `gvisor-trace` must report
      # gVisor's OWN kernel (so the class really selects runsc, not a silent runc fallback), AND the
      # sentry's boot log must then contain the syscall that pod made. The second half is what makes
      # this a SENSOR assertion rather than a boundary one: the RuntimeClass can be perfectly correct
      # while `strace` is off, and 2.3.2 would report an empty trail — "gVisor hid everything" —
      # about a sandbox that simply was not being traced.
      got=$(box_ssh "${BOX}" "
        sudo rm -f /var/log/runsc-trace/* 2>/dev/null
        kubectl delete pod sbxchk-gvt --ignore-not-found --now >/dev/null 2>&1
        kubectl run sbxchk-gvt --restart=Never --quiet --overrides='{\"spec\":{\"runtimeClassName\":\"gvisor-trace\"}}' \
          --image=${AGENT_IMAGE} --image-pull-policy=IfNotPresent \
          --command -- /bin/sh -c 'uname -r; cat \$HOME/.ssh/id_rsa; true' >/dev/null 2>&1
        for _ in \$(seq 1 90); do
          case \"\$(kubectl get pod sbxchk-gvt -o jsonpath='{.status.phase}' 2>/dev/null)\" in
            Succeeded | Failed) break ;;
          esac
          sleep 2
        done
        kern=\$(kubectl logs sbxchk-gvt 2>/dev/null | head -1)
        kubectl delete pod sbxchk-gvt --ignore-not-found --now --wait=false >/dev/null 2>&1
        sleep 3
        traced=\$(sudo bash -c 'grep -ahcE \" E open(at)?\\(\" /var/log/runsc-trace/*boot* 2>/dev/null | head -1' || echo 0)
        echo \"kernel=\${kern:-none} traced=\${traced:-0}\"" 2>/dev/null | tail -1)
      echo "    gvisor-trace probe: ${got}"
      tkern=$(echo "${got}" | sed -n 's/.*kernel=\([^ ]*\).*/\1/p')
      traced=$(echo "${got}" | sed -n 's/.*traced=\([0-9]*\).*/\1/p')
      case "${tkern}" in
        *gvisor*)
          if [ "${traced:-0}" -gt 0 ]; then
            pass "gVisor trace: the pod ran on gVisor's own kernel (${tkern}) AND the sentry wrote ${traced} of its syscalls to the boot log — the only sensor that can see inside this boundary is armed"
          else
            fail "gVisor trace: the class engaged (${tkern}) but the sentry's boot log holds NO syscalls — strace is off, so 2.3.2 would report an empty trail as if gVisor had hidden everything"
          fi
          ;;
        "${NODE_KERNEL}") fail "gvisor-trace pod reports the NODE kernel (${tkern}) — the RuntimeClass was accepted and runc ran anyway, the silent fallback" ;;
        *) fail "gvisor-trace pod: unexpected kernel '${tkern}' (traced=${traced:-0})" ;;
      esac
      ;;

    k8s-api-audit)
      # The CONTROL-PLANE sensor. Asserted from the LOG, never from the flag, and for a reason
      # specific to this one: a policy file the apiserver cannot parse does NOT stop k3s. It logs the
      # error and comes up with auditing OFF — after which every 2.3.x control-plane row reports "the
      # control plane recorded nothing" about a cluster that was never recording. That is this repo's
      # silent-fallback failure wearing the audit trail's clothes.
      #
      # The trigger is a SERVICE-ACCOUNT request, not a plain `kubectl get`. `system:serviceaccount:
      # <ns>:<name>` is the exact field the per-attack mapping reads for `k8s_sa_token`, and admin
      # traffic would exercise a different rule in the policy — proving the log works while leaving
      # the one clause the lesson depends on untested.
      got=$(box_ssh "${BOX}" "
        tok=\$(kubectl create token default 2>/dev/null || echo)
        [ -n \"\${tok}\" ] && curl -sk -o /dev/null -H \"Authorization: Bearer \${tok}\" https://127.0.0.1:6443/api
        sleep 3
        sudo grep -c 'system:serviceaccount:default:default' /var/lib/rancher/k3s/server/logs/audit.log 2>/dev/null || echo 0" 2>/dev/null | tail -1)
      flags=$(box_ssh "${BOX}" "sudo grep -c 'audit-policy-file' /etc/rancher/k3s/config.yaml 2>/dev/null || echo 0" 2>/dev/null | tail -1)
      echo "    k8s api audit: service-account events=${got:-0}, policy configured=${flags:-0}"
      if [ "${got:-0}" -gt 0 ]; then
        pass "k8s API audit: a service-account request was written to the audit log — the control-plane sensor is watching, and its events carry the pod's identity"
      else
        fail "k8s API audit: no service-account event reached /var/lib/rancher/k3s/server/logs/audit.log — the apiserver is not auditing (a policy it could not parse starts the cluster with audit OFF), so 2.3.x's control-plane column would be a false blank"
      fi
      ;;

    85-kata-debug-kernel)
      # 2.3.3's in-guest sensor needs a guest kernel carrying BTF, and the DEFAULT Kata guest kernel
      # has none. Assert from INSIDE a POD booted with the annotation — and assert the DEFAULT guest
      # too, because that contrast is the only proof the annotation did anything.
      #
      # The kernel STRING cannot be the test here: both kernels report 6.18.35, since the debug build
      # carries the same version. A uname comparison would pass on a guest that never got the
      # annotation, and 2.3.3 would then report "no BTF" as a property of Kata rather than of a
      # substrate edit that missed. BTF presence is the discriminator.
      dk=$(box_ssh "${BOX}" "cat /etc/kata-containers-debug-kernel 2>/dev/null" 2>/dev/null | tail -1)
      if [ -z "${dk}" ]; then
        fail "kata debug kernel: /etc/kata-containers-debug-kernel is absent — the substrate did not run"
      else
        # shellcheck disable=SC2016  # must expand inside the guest, not here
        GUEST_BTF='echo $(uname -r) $(test -e /sys/kernel/btf/vmlinux && echo btf-present || echo btf-absent)'
        plain=$(k8s_pod_output "${BOX}" sbxchk-kdk-default "kata-qemu" sh -c "'${GUEST_BTF}'")
        annot=$(box_ssh "${BOX}" "
          kubectl delete pod sbxchk-kdk-debug --ignore-not-found --now >/dev/null 2>&1
          kubectl run sbxchk-kdk-debug --restart=Never --quiet \
            --overrides='{\"spec\":{\"runtimeClassName\":\"kata-qemu\"},\"metadata\":{\"annotations\":{\"io.katacontainers.config.hypervisor.kernel\":\"${dk}\"}}}' \
            --image=${AGENT_IMAGE} --image-pull-policy=IfNotPresent --command -- sh -c '${GUEST_BTF}' >/dev/null 2>&1
          for _ in \$(seq 1 90); do
            case \"\$(kubectl get pod sbxchk-kdk-debug -o jsonpath='{.status.phase}' 2>/dev/null)\" in
              Succeeded | Failed) break ;;
            esac
            sleep 2
          done
          kubectl logs sbxchk-kdk-debug 2>/dev/null | tail -1
          kubectl delete pod sbxchk-kdk-debug --ignore-not-found --now --wait=false >/dev/null 2>&1" 2>/dev/null | tail -1)
        echo "    kata default guest: ${plain:-?}"
        echo "    kata DEBUG guest  : ${annot:-?}   (${dk})"
        if echo "${annot}" | grep -q 'btf-present'; then
          pass "kata debug kernel: the annotation swapped the kernel — BTF is present in-guest, so 2.3.3's sidecar has something to attach against"
        else
          fail "kata debug kernel: '${annot:-no output}' — the annotation did not take effect. Under kata-deploy the qemu config is a SYMLINK and \`sed -i\` replaces it instead of editing the target, which leaves the shim reading an unedited file and parks the pod in ContainerCreating."
        fi
      fi
      ;;

    kata-debug-kernel)
      # 2.2.3's in-guest sensor needs a guest kernel carrying CONFIG_AUDITSYSCALL + BTF. The DEFAULT
      # Kata guest kernel has neither; the shipped debug kernel has both, selected per-run by the
      # `kernel` annotation. Assert from INSIDE a guest booted with that annotation: the debug kernel
      # string AND /sys/kernel/btf/vmlinux present. A default guest (no annotation) exposes neither, so
      # "btf-present" here is proof the annotation actually swapped the kernel rather than being ignored.
      dk=$(box_ssh "${BOX}" "cat /etc/kata-containers-debug-kernel 2>/dev/null" 2>/dev/null | tail -1)
      got=$(box_ssh "${BOX}" "sudo nerdctl run --rm --net none --runtime io.containerd.kata.v2 --annotation io.katacontainers.config.hypervisor.kernel=${dk} ${ALPINE} sh -c 'echo \$(uname -r) \$(test -e /sys/kernel/btf/vmlinux && echo btf-present || echo btf-absent)'" 2>/dev/null | tail -1)
      echo "    kata debug-kernel guest: ${got}   (debug kernel: ${dk})"
      if echo "${got}" | grep -q 'btf-present'; then
        pass "kata debug kernel: BTF present in-guest via annotation — an in-guest sensor can attach (2.2.3)"
      else
        fail "kata debug kernel: '${got}' — the annotation did not swap the kernel (no BTF in-guest); 2.2.3's in-guest sensor path is dead"
      fi
      ;;

    auditd-guest)
      # 2.2.4's host sensor, INSIDE the NAT guest. The substrate runs after 50-nat-vm/40-openshell, so
      # box_ssh already lands in the guest (the 50-nat-vm arm above asserts the private-IP re-point);
      # this checks the sensor there. Assert auditd is RUNNING and its keyed rules are loaded — the lesson
      # needs a live, armed sensor to make its point (that even so, the rootless workload evades it); a
      # dead auditd would make "auditd attributed none of the attacks" meaningless rather than a finding.
      where=$(box_ssh "${BOX}" "hostname 2>/dev/null" 2>/dev/null | tail -1)
      active=$(box_ssh "${BOX}" "systemctl is-active auditd 2>/dev/null || echo inactive" 2>/dev/null | tail -1)
      rules=$(box_ssh "${BOX}" "sudo auditctl -l 2>/dev/null | grep -c sbx_" 2>/dev/null | tail -1)
      # The two auditd.conf settings the lesson depends on MUST be live, not just on disk — a restart
      # applies them (apt starts auditd on the defaults). Assert them so the rotation/format intermittency
      # they fix cannot silently return: RAW format keeps the trail greppable, and a large max_log_file
      # keeps a whole run in one segment instead of rotating the sensitive records out mid-run.
      fmt=$(box_ssh "${BOX}" "sudo grep -i '^log_format' /etc/audit/auditd.conf | awk '{print \$3}'" 2>/dev/null | tail -1)
      mlf=$(box_ssh "${BOX}" "sudo grep '^max_log_file ' /etc/audit/auditd.conf | awk '{print \$3}'" 2>/dev/null | tail -1)
      echo "    auditd host: ${where}   log_format=${fmt}   max_log_file=${mlf}"
      if [ "${active}" = "active" ] && [ "${rules:-0}" -gt 0 ] && [ "${fmt}" = "RAW" ] && [ "${mlf:-0}" -ge 500 ]; then
        pass "auditd (guest): active, ${rules} rules, log_format=RAW, max_log_file=${mlf} — the trail is stable and greppable"
      else
        fail "auditd (guest): active='${active}' rules='${rules:-0}' log_format='${fmt}' max_log_file='${mlf}' — the sensor or its config is wrong, 2.2.4's trail would be a false blank or intermittent"
      fi
      ;;
  esac
done

[ "${FAILED}" -eq 0 ] || die "boundary assertions FAILED for ${BOX} — the box is not what the lesson claims."
