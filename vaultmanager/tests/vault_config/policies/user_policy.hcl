# Default policy for user
path "users/" {
  capabilities = ["list"]
}

path "users/{{USER_NAME}}/*" {
  capabilities = ["read", "create", "update", "delete", "list"]
}
