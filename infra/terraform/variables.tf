variable "zone" {
  description = "Scaleway zone every lesson box is created in."
  type        = string
  default     = "fr-par-1"
}

variable "ssh_key_name" {
  description = <<-EOT
    Name of the Scaleway IAM SSH key the boxes trust. Deliberately a THROWAWAY keypair rather than
    your personal one: every box here runs a rogue-agent suite and is destroyed within the hour, so
    the credential that reaches it should be disposable too. No private key ever enters this repo.
  EOT
  type        = string
  default     = "sandboxing-tutorial"
}

variable "up" {
  description = <<-EOT
    Which lessons should exist right now. This is what makes teardown honest: `up.sh` adds a name,
    `down.sh` removes it, and an empty list means Terraform itself asserts that nothing is running.
    A box that is not in this list is not billed, and state — not a text file someone forgot to
    update — is what proves it.
  EOT
  type        = list(string)
  default     = []
}
