variable "lesson" {
  description = "Lesson directory name, e.g. lesson-03-container-gvisor."
  type        = string
}

variable "name" {
  description = "Server name in the Scaleway console. Always sbx-* — down.sh sweeps on that prefix."
  type        = string
}

variable "kind" {
  description = "'vm' (Scaleway VM) or 'baremetal' (Elastic Metal)."
  type        = string

  validation {
    condition     = contains(["vm", "baremetal"], var.kind)
    error_message = "kind must be 'vm' or 'baremetal'."
  }
}

variable "type" {
  description = "Commercial type: a VM type (PLAY2-NANO) or a metal offer (EM-A116X-SSD)."
  type        = string
}

variable "image" {
  description = "Marketplace image label for a VM, e.g. ubuntu_noble. Ignored for metal, which resolves an OS id."
  type        = string
  default     = "ubuntu_noble"
}

variable "root_volume_gb" {
  description = "Root volume size. Not a safe default — the Kata stack needs 40 and the 8 GB stock volume dies mid-install."
  type        = number
  default     = 20
}

variable "zone" {
  type = string
}

variable "ssh_key_id" {
  description = "IAM id of the throwaway key. Metal takes key ids directly at install time."
  type        = string
}

variable "ssh_public_key" {
  description = "Public half of the same key, handed to cloud-init so the unprivileged user can be reached."
  type        = string
}
