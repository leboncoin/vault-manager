# Default policy for user
path "users/{{USER_NAME}}/*" {
  capabilities = ["read", "create", "update", "delete", "list"]
}