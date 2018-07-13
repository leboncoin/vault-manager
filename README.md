# vault-manager

vault-manager is a CLI which allows to keep all your Hashicorp Vault configuration in a directory.

## How does it works

vault-manager is a CLI which use modules to interact with Vault.
Each module is and should be designed to interact woth a Vault part ('policies' module allows to manage policies, 'auth' module allows to manage authentication methods etc...)

## Installation and usage

### Prequesites

vault-manager has been developed using python 3.6.5 and works fine with this version.
Some modules may not work using python 2.

vault-manager is using [pbr](https://pypi.org/project/pbr/) to build its package.
First, you need to install pbr

```bash
$> pip install pbr
```

### Installation

Once pbr installed, you'll be able to create the python package

```bash
$> python setup.py sdist
```

this will create the python package in a newly created `dist` folder in the project root folder.

You can now install the python package

```bash
pip install dist/vaultmanager-1.0.9.tar.gz
```

## How to use it

Once the package installed, you can now use the following command

```bash
$> vault-manager -h
usage: vault-manager [-h] [-v] [-d] {secret,auth,ldap,policies,audit} ...

Vault configuration manager

positional arguments:
  {secret,auth,ldap,policies,audit}
    secret              secret management
    auth                auth management
    ldap                ldap management
    policies            policies management
    audit               audit management

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         enable verbose mode
  -d, --dry-run         run in dry mode: No API calls
```

You can print the help for each module by typing

```bash
vault-manager <module> -h
```

Each module can be run with `--dry-run` or `--verbose` args

e.g.

```bash
$> vault-manager -vvvv -d ldap --list-groups
```

**NOTE:** For all modules, the three following environment variables have to be set:

* `VAULT_ADDR` : The Vault API address (e.g.: <https://vault.domain.com:8200>)
* `VAULT_TOKEN` : A Vault token with needed rights depending on the module you'll be using
* `VAULT_CONFIG` : The path to the folder containing vault-manager modules configuration files

**NOTE:** vault-manager configuration folder is containing all configuration files used by modules to configure Vault. You can find an exemple of this folder by looking at `vault_config_template`

## Modules

All vault-manager modules will be detailed in this section

## audit

The **audit** module allows to manage audit devices in Vault

```bash
$> vault-manager <module> -h
usage: vault-manager audit [-h] [--push]

optional arguments:
  -h, --help  show this help message and exit
  --push      Push audit configuration to Vault
```

### Configuration file

One configuration file is needed by this module

* `$VAULT_CONFIG/audit-devices.yml`

e.g. **audit-devices.yml**

```yaml
---
audit-devices:
  - type: file
    path: file_log
    description: File audit log
    options:
      file_path: /var/log/vault_audit.log
      #log_raw: (optional) default false
      #hmac_accessor: (optional) default true
      #mode: (optional) default 0600
      #format: (optional) default json - (json|jsonx)
      #prefix: (optional) default empty - prefix_
```

### arguments

#### push

`vault-manager audit --push`

**push** command will synchronize audit devices in configuration file with the Vault instance. The audit device mount point must be unique and is used as an unique identifier.

**NOTE:** If other parameters than `type` and `path` are modified, the audit device will remains enabled, only changed parameters will be modified.

**WARNING:** Any audit device enabled in Vault but not in the configuration file will be disabled.

## auth

```bash
$> vault-manager auth -h
usage: vault-manager auth [-h] [--push]

optional arguments:
  -h, --help  show this help message and exit
  --push      Push auth methods to Vault
```

### Configuration file

One configuration file is needed by this module

* `$VAULT_CONFIG/auth-methods.yml`

e.g. **auth-methods.yml**

```yaml
---
auth-methods:
  - type: token
    path: token
    description: token based credentials
    tuning:
      default_lease_ttl: 0
      max_lease_ttl: 0
  - type: ldap
    path: ldap
    description: LDAP authentication
    tuning:
      default_lease_ttl: 43200
      max_lease_ttl: 0
    auth_config:
      # All available parameters here
      # https://www.vaultproject.io/api/auth/ldap/index.html#configure-ldap
      binddn: cn=<CN>,ou=<OU>,dc=<DC>
      bindpass: VAULT{{path/to/secret:password}}
      case_sensitive_names: false
      deny_null_bind: true
      discoverdn: false
      groupattr: cn
      groupdn: OU=<GROUP>,DC=<DC>
      groupfilter: (|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}}))
      insecure_tls: false
      starttls: false
      tls_max_version: tls12
      tls_min_version: tls12
      url: ldap://<URL>
      userattr: samaccountname
      userdn: OU=<OU>,DC=<DC>
  - type: approle
    path: approle
    description: Approle authentication
    tuning:
      default_lease_ttl: 43200
      max_lease_ttl: 0
    auth_config:
      concourse:
        # All available parameters here
        # https://www.vaultproject.io/api/auth/approle/index.html#create-new-approle
        role_name: concourse
        policies: [service_concourse_policy]
      jenkins:
        role_name: jenkins
        policies: [service_jenkins_policy]
```

### arguments

#### push

`vault-manager auth --push`

**push** command will synchronize authentication methods in configuration file with the Vault instance. The authentication method mount point must be unique and is used as an unique identifier.

**NOTE:** If other parameters than `type` and `path` are modified, the authentication method will remains enabled, only changed parameters will be modified.

**WARNING:** Any authentication method enabled in Vault but not in the configuration file will be disabled.

## ldap

**ldap** module is in charge of interacting with your LDAP contacts

```bash
$> vault-manager ldap -h
usage: cli.py ldap [-h] [--list-groups] [--create-policies]
                   [--manage-ldap-groups [LDAP_mount_point]]
                   [--manage-ldap-users [LDAP_mount_point]]
                   [--create-groups-secrets [groups_secrets_folder]]
                   [--create-users-secrets [users_secrets_folder]]

optional arguments:
  -h, --help            show this help message and exit
  --list-groups         List LDAP groups
  --create-policies     Create policies from LDAP groups and users
  --manage-ldap-groups [LDAP_mount_point]
                        Create LDAP groups in Vault with associated policies
                        at specified mount point
  --manage-ldap-users [LDAP_mount_point]
                        Create LDAP users in Vault with associated policies
                        and groups at specified mount point
  --create-groups-secrets [groups_secrets_folder]
                        Create a folder for each group in
                        <groups_secrets_folder>
  --create-users-secrets [users_secrets_folder]
                        Create a folder for each user in
                        <users_secrets_folder>
```

### Configuration file

Three files are needed by this module

* `$VAULT_CONFIG/ldap.yml`
* `$VAULT_CONFIG/policies/policies.yml`
* `$VAULT_CONFIG/policies/group_policy.hcl`
* `$VAULT_CONFIG/policies/user_policy.hcl`

**ldap.yml** is the configuration file of the **ldap** module

```yaml
---
ldap:
  server: ldap://<URL>
  username: <LDAP_username>
  password: <LDAP_password_Vault_path>
  group_dn: OU=<group1>,OU=<group2>,DC=<company>
  user_dn: OU=<users1>,OU=<users2>,DC=<company>
```

**policies.yml** is used by **ldap** module.

e.g. **policies.yml**

```yaml
---
general:
  group:
    # Policy used to generate groups policies
    default_policy: group_policy.hcl
    # The root policy will be applied to the following groups
    # in addition of their own policy
    root: [root_group_1, root_group_2]
  user:
    # Policy used to generate users policies
    default_policy: user_policy.hcl
    # The root policy will be applied to the following users
    # in addition of their own policy
    root: [root_user_1, root_user_2]

# By default no groups are added
# All have to be specified
groups:
  groups_to_add:
    - <LDAP_group_name_1>
    - <LDAP_group_name_2>

# By default all users are added
# Each user to exclude have to be listed below
users:
  users_to_exclude:
    - <user_1>
    - <user_2>
```

**group_policy.hcl** contains the default policy for groups. The pattern `{{GROUP_NAME}}` will be replaced by the group name.

e.g. **group_policy.hcl**

```hcl
# Groups default policy
path "groups/" {
  capabilities = ["list"]
}

path "groups/{{GROUP_NAME}}/*"  {
  capabilities = ["read", "create", "update", "delete", "list"]
}
```

**user_policy.hcl** contains the default policy for users. The pattern `{{USER_NAME}}` will be replaced by the user name.

e.g. **user_policy.hcl**

```hcl
# Default policy for user
path "users/" {
  capabilities = ["list"]
}

path "users/{{USER_NAME}}/*" {
  capabilities = ["read", "create", "update", "delete", "list"]
}
```

### arguments

#### list-groups

`vault-manager ldap --list-groups`

**list-groups** will display found LDAP groups

#### create-policies

`vault-manager ldap --create-policies`

**create-policies** will create all policies.

* Groups policies for groups specified in the **policies.yml** under `groups_to_add`
* Users policies for all users members of the groups specified in **policies.yml** under `groups_to_add` except users specified in `users_to_exclude`

Two subfolders will be created in `$VAULT_CONFIG/policies`

* `users` under which will be created users policies
* `groups` under which will be created groups policies

Each user policy will be created with the following file name
`<user_name>.hcl`

Each group policy will be created with the following file name
`<group_name>.hcl`

**NOTE:** If a policy file already exists, it will not be overwritten

**WARNING:** If a group or user previously included in **policies.yml** is removed, all associated policies will be deleted

#### manage-ldap-groups

`vault-manager ldap --manage-ldap-groups [LDAP_mount_point]`

**manage-ldap-groups** will create groups found in LDAP under the LDAP_mount_point Vault configuration. See Vault documentation for more details [create-update-ldap-group](https://www.vaultproject.io/api/auth/ldap/index.html#create-update-ldap-group)
The correct policy for the group will be applied

#### manage-ldap-users

`vault-manager ldap --manage-ldap-users [LDAP_mount_point]`

**manage-ldap-users** will create users found in LDAP under the LDAP_mount_point Vault configuration. See Vault documentation for more details [create-update-ldap-user](https://www.vaultproject.io/api/auth/ldap/index.html#create-update-ldap-user)
The correct policy for the group will be applied

#### create-groups-secrets

`vault-manager ldap --create-groups-secrets [groups_secrets_folder]`

**create-groups-secrets** will create/delete a secret 'folder' for each LDAP group at `groups_secrets_folder/{{GROUP_NAME}}`.

**NOTE:** If the folder already exists, it will not be modified

**WARNING:** If secrets 'folder' have to be deleted (because the group doesn't exists in configuration anymore), **all secrets in this 'folder' will be lost**

#### create-users-secrets

`vault-manager ldap --create-users-secrets [users_secrets_folder]`

**create-users-secrets** will create/delete a secret 'folder' for each LDAP user at `users_secrets_folder/{{USER_NAME}}`.

**NOTE:** If the folder already exists, it will not be modified

**WARNING:** If secrets 'folder' have to be deleted (because the user doesn't exists in configuration anymore), **all secrets in this 'folder' will be lost**

## policies

The **policies** module allows to manage policies in Vault

```bash
$> vault-manager policies -h
usage: vault-manager policies [-h] [--pull] [--push]

optional arguments:
  -h, --help  show this help message and exit
  --pull      Pull distant policies from Vault
  --push      Push local policies to Vault
```

### arguments

#### pull

`vault-manager policies --pull`

**pull** will fetch all policies in Vault and create policy files in `$VAULT_CONFIG/policies`

**IMPORTANT:** Every policy in Vault have to match the following naming convention
`<keyword>_<policy_name>_policy`.
e.g. `user_<policy_name>_policy`, `service_<policy_name>_policy`
If a policy does not match this naming pattern, it will not be pulled

**NOTE:** Policies already in Vault by default `default` and `root` will never be pulled

A subfolder for each `keyword` found in policies will be created and associated policies files will be created under it.
e.g. Following policies in Vault

```bash
$> vault policy list
default
user_bob_policy
group_admins_policy
service_jenkins_policy
service_concourse_policy
root
```

will create the following folders tree in the `$VAULT_CONFIG/policies` folder

```tree
policies
├── user
│   └── bob.hcl
├── group
│    └── admins.hcl
└── service
    ├── jenkins.hcl
    └── concourse.hcl
```

#### push

`vault-manager policies --push`

**push** will push all policies found in `$VAULT_CONFIG/policies` to Vault.
Policies naming works the same way than describe above

**NOTE:** Policies already in Vault by default `default` and `root` will never be deleted/modified

Only policies in subfolders will be pushed to Vault
e.g. Following folders tree

```tree
policies
├── user
│   └── bob.hcl
├── group
│    └── admins.hcl
└── service
    ├── jenkins.hcl
    └── concourse.hcl
```

will create the following policies in vault

```bash
$> vault policy list
default
user_bob_policy
group_admins_policy
service_jenkins_policy
service_concourse_policy
root
```

## secret

The secret module allows to manage secrets engines in Vault

```bash
$> vault-manager secret -h
usage: vault-manager secret [-h] [--push]

optional arguments:
  -h, --help  show this help message and exit
  --push      Push secrets engines to Vault
```

### Configuration file

One configuration file is needed by this module

* `$VAULT_CONFIG/secrets-engines.yml`

e.g. **secrets-engines.yml**

```yaml
---
secrets-engines:
  - type: kv
    path: services
    description:
    tuning:
      default_lease_ttl: 1800
      max_lease_ttl: 1800
  - type: kv
    path: users
    description: Users specific folders
    tuning:
      default_lease_ttl: 0
      max_lease_ttl: 0
```

### arguments

#### push

`vault-manager secret --push`

**push** command will synchronize secrets engines in configuration file with the Vault instance. The secret engine mount point must be unique and is used as an unique identifier.

**NOTE** If other parameters than `type` and `path` are modified, the audit device will remains enabled, only changed parameters will be modified.

**WARNING** Any secret engine enabled in Vault but not in the configuration file will be disabled. All secrets in it will be lost.
