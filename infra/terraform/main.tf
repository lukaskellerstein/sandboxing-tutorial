locals {
  # lessons.json is the single source of truth and is read, not duplicated. `_comment` is the
  # rationale that used to live in lessons.conf's header; strip it before it looks like a lesson.
  catalogue = { for k, v in jsondecode(file("${path.module}/lessons.json")) : k => v if k != "_comment" }

  # Only the lessons asked for. An unknown name fails here, loudly, instead of silently creating
  # nothing and leaving the reader to wonder why ssh never came up.
  active = { for name in var.up : name => local.catalogue[name] }
}

# The public half of the throwaway key, so cloud-init can authorise the unprivileged user it makes.
# Read from Scaleway rather than from a local path: the key that matters is the one the account
# actually trusts, and reading it here means a mismatch fails at plan time.
data "scaleway_iam_ssh_key" "throwaway" {
  name = var.ssh_key_name
}

module "box" {
  source   = "./modules/lesson-box"
  for_each = local.active

  lesson         = each.key
  name           = "sbx-${replace(each.key, "lesson-", "")}"
  kind           = each.value.kind
  type           = each.value.type
  image          = each.value.image
  root_volume_gb = try(each.value.root_volume_gb, 20)
  zone           = var.zone
  ssh_key_id     = data.scaleway_iam_ssh_key.throwaway.id
  ssh_public_key = data.scaleway_iam_ssh_key.throwaway.public_key
}
