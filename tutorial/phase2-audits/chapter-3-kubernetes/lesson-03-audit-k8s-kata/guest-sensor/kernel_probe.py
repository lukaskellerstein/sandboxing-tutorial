"""What a kernel-side sensor could and could not do from inside the Kata guest.

Run by ``sensor.sh`` in the privileged sidecar. It answers two questions the lesson reports as
findings rather than as prose, because both were *predictions* in the syllabus and only one held:

* **audit netlink** — the syllabus's G1 reframe said an in-guest auditd/eBPF sidecar would work under
  Kubernetes where it failed under nerdctl, because a privileged pod has "the guest's init context".
  It does not. Measured here, live, every time.
* **bpf()** — whether the guest kernel would in fact host an eBPF sensor, asked by actually LOADING a
  minimal program rather than by checking for BTF and hoping.

Both print one ``SBX_*`` line, which ``main.py`` parses. Nothing here touches the workload.
"""

from __future__ import annotations

import ctypes
import os
import socket
import struct

NETLINK_AUDIT = 9
AUDIT_GET = 1000
#: BPF_PROG_LOAD, and BPF_PROG_TYPE_SOCKET_FILTER — the least privileged program type there is, so a
#: refusal cannot be blamed on asking for something exotic.
BPF_PROG_LOAD = 5
BPF_PROG_TYPE_SOCKET_FILTER = 1
SYS_BPF_X86_64 = 321


def audit_netlink() -> str:
    """Try to talk to the guest kernel's audit subsystem. Returns a short verdict string."""
    try:
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_AUDIT)
    except OSError as exc:
        return f"socket-failed:{exc.errno}"
    try:
        sock.settimeout(5)
        sock.bind((0, 0))
        # NLM_F_REQUEST | NLM_F_ACK
        sock.send(struct.pack("=IHHII", 16, AUDIT_GET, 0x0005, 1, 0))
        reply = sock.recv(8192)
        if struct.unpack("=IHHII", reply[:16])[1] == 2:  # NLMSG_ERROR
            err = struct.unpack("=i", reply[16:20])[0]
            return "ok" if err == 0 else f"{os.strerror(-err)}"
        return "ok"
    except Exception as exc:  # noqa: BLE001 - a probe reports whatever went wrong
        return f"{type(exc).__name__}"
    finally:
        sock.close()


def bpf_load() -> str:
    """Load a two-instruction eBPF program. Returns "loaded" or the errno name."""
    # r0 = 0 ; exit  — the smallest verifiable program.
    insns = struct.pack("=BBHi", 0xB7, 0, 0, 0) + struct.pack("=BBHi", 0x95, 0, 0, 0)
    insn_buf = ctypes.create_string_buffer(insns)
    license_buf = ctypes.create_string_buffer(b"GPL\0")
    attr = struct.pack(
        "=IIQQIIQII16s",
        BPF_PROG_TYPE_SOCKET_FILTER,
        2,  # insn_cnt
        ctypes.addressof(insn_buf),
        ctypes.addressof(license_buf),
        0,  # log_level
        0,  # log_size
        0,  # log_buf
        0,  # kern_version
        0,  # prog_flags
        b"sbxprobe\0",
    )
    attr_buf = ctypes.create_string_buffer(attr, len(attr))
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.syscall.restype = ctypes.c_long
    ctypes.set_errno(0)
    fd = libc.syscall(
        ctypes.c_long(SYS_BPF_X86_64),
        ctypes.c_long(BPF_PROG_LOAD),
        ctypes.byref(attr_buf),
        ctypes.c_long(len(attr)),
    )
    if fd >= 0:
        os.close(fd)
        return "loaded"
    return os.strerror(ctypes.get_errno())


print(f"SBX_AUDIT_NETLINK {audit_netlink()}")
print(f"SBX_BPF_LOAD {bpf_load()}")
print(f"SBX_BTF {'present' if os.path.exists('/sys/kernel/btf/vmlinux') else 'absent'}")
