# Default policy for group
path "groups/{{GROUP_NAME}}/*"  {
  capabilities = ["read", "create", "update", "delete", "list"]
}