terraform {
  required_providers {
    scaleway = {
      source = "scaleway/scaleway"
    }
  }
}

# --- a VM (console: Compute -> CPU & GPU Instances) ---------------------------
#
# What lessons 1-5 use. Boots in under a minute, has no quota wall, and was measured to produce the
# identical scorecard to Elastic Metal — see the rationale block in lessons.json.

resource "scaleway_instance_server" "vm" {
  count = var.kind == "vm" ? 1 : 0

  name  = var.name
  type  = var.type
  image = var.image
  zone  = var.zone

  # A dynamic address, not a flexible one, and that is a cost decision: a flexible IP keeps billing
  # after the server it was attached to is gone, which is exactly the orphan this repo tries not to
  # leave behind. A dynamic one dies with the box.
  enable_dynamic_ip = true

  root_volume {
    size_in_gb            = var.root_volume_gb
    delete_on_termination = true
  }

  user_data = {
    cloud-init = templatefile("${path.module}/cloud-init.yaml.tftpl", {
      hostname       = var.lesson
      ssh_public_key = var.ssh_public_key
    })
  }

  tags = ["sandboxing-tutorial", var.lesson, "disposable"]
}

# --- Elastic Metal (console: Bare Metal -> Elastic Metal) ---------------------
#
# No lesson currently asks for this. It stays because chapter 4's single-node OpenShift genuinely
# does need metal, and because "we measured that VMs suffice" is a claim about lessons 1-5, not a
# claim that metal is never right.

data "scaleway_baremetal_os" "metal" {
  count = var.kind == "baremetal" ? 1 : 0

  zone    = var.zone
  name    = "Ubuntu"
  version = "24.04"
}

resource "scaleway_baremetal_server" "metal" {
  count = var.kind == "baremetal" ? 1 : 0

  name  = var.name
  zone  = var.zone
  offer = var.type
  os    = data.scaleway_baremetal_os.metal[0].os_id

  ssh_key_ids = [var.ssh_key_id]
  tags        = ["sandboxing-tutorial", var.lesson, "disposable"]
}
