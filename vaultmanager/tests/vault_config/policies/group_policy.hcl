# Groups default policy
path "groups/" {
  capabilities = ["list"]
}

path "groups/{{GROUP_NAME}}/*" {
  capabilities = ["read", "create", "update", "delete", "list"]
}
