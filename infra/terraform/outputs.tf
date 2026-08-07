output "boxes" {
  description = "Everything the shell scripts need to reach a box. Consumed by lib.sh via `terraform output -json`."
  value = {
    for k, m in module.box : k => {
      id         = m.id
      ip         = m.ip
      user       = m.user
      kind       = m.kind
      type       = m.type
      substrates = local.catalogue[k].substrates
    }
  }
}

output "up" {
  description = "Which lessons Terraform believes are running. `down.sh` compares this against the account."
  value       = keys(module.box)
}
