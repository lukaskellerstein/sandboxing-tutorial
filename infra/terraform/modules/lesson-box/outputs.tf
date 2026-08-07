locals {
  is_vm = var.kind == "vm"
}

output "id" {
  value = local.is_vm ? scaleway_instance_server.vm[0].id : scaleway_baremetal_server.metal[0].id
}

# `public_ips` is a list covering both families, so the v4 address has to be selected rather than
# indexed — [0] is whichever the API happened to return first, and an IPv6 there sends every later
# ssh and rsync to an address the scripts cannot reach.
output "ip" {
  value = local.is_vm ? one([
    for ip in scaleway_instance_server.vm[0].public_ips : ip.address if ip.family == "inet"
  ]) : scaleway_baremetal_server.metal[0].ipv4[0].address
}

# The login user differs by product and getting it wrong looks like a broken key rather than a wrong
# name: a VM is reached as the unprivileged `agent` cloud-init creates (lesson 2 needs rootless),
# Elastic Metal as its own `ubuntu`.
output "user" {
  value = local.is_vm ? "agent" : "ubuntu"
}

output "kind" {
  value = var.kind
}

output "type" {
  value = var.type
}
