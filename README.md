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
  -s, --skip-tls        disable TLS verification
```

You can print the help for each module by typing

```bash
vault-manager <module> -h
```

Each module can be run with `--dry-run`, `--verbose` or `--skip-tls` args

e.g.

```bash
$> vault-manager -vvvv -d -s ldap --list-groups
```

**NOTE:** For all modules, the three following environment variables have to be set:

* `VAULT_ADDR` : The Vault API address (e.g.: <https://vault.domain.com:8200>)
* `VAULT_TOKEN` : A Vault token with needed rights depending on the module you'll be using
* `VAULT_CONFIG` : The path to the folder containing vault-manager modules configuration files

**NOTE:** vault-manager configuration folder is containing all configuration files used by modules to configure Vault. You can find an exemple of this folder by looking at `vault_config_template`

## Modules

All vault-manager modules will be detailed in this section

## kv

**kv** modules allows to perform actions on the key/value store

```bash
$> vault-manager kv -h
usage: cli.py kv [-h] [--export PATH_TO_EXPORT]
                 [--copy COPY_FROM_PATH COPY_TO_PATH]
                 [--delete PATH_TO_DELETE]

optional arguments:
  -h, --help            show this help message and exit
  --export PATH_TO_EXPORT
                        export kv store from specified path PATH_TO_EXPORT
                        from $VAULT_ADDR instance to $VAULT_TARGET_ADDR at the
                        same path. $VAULT_TOKEN is used for $VAULT_ADDR and
                        $VAULT_TARGET_TOKEN is used for $VAULT_TARGET_ADDR
  --copy COPY_FROM_PATH COPY_TO_PATH
                        copy kv store from specified path COPY_FROM_PATH from
                        $VAULT_ADDR instance to $VAULT_TARGET_ADDR at path
                        COPY_TO_PATH. $VAULT_TOKEN is used for $VAULT_ADDR and
                        $VAULT_TARGET_TOKEN is used for $VAULT_TARGET_ADDR
  --delete PATH_TO_DELETE
                        delete PATH_TO_DELETE and all secrets under it from
                        $VAULT_ADDR instance. $VAULT_TOKEN is used for
                        $VAULT_ADDR
```

### Configuration file

There is no configuration file needed by this module

### arguments

#### export

`vault-manager kv --export PATH_TO_EXPORT`

**export** will export k/v tree under PATH_TO_EXPORT.

**NOTE:** In addition of VAULT_ADDR and VAULT_TOKEN environment variable, the two following are needed

* `VAULT_TARGET_ADDR` : Vault URL which will be the target for the exported key/value store
* `VAULT_TARGET_TOKEN` : Vault token with correct right for `VAULT_TARGET_ADDR`

All secrets under PATH_TO_EXPORT on $VAULT_ADDR will be exported to PATH_TO_EXPORT on $VAULT_TARGET_ADDR.

**WARNING:** All secrets already existing on $VAULT_TARGET_ADDR will be overwritten

**NOTE:** Secrets already existing on $VAULT_TARGET_ADDR but not existing on $VAULT_ADDR will not be deleted

#### copy

`vault-manager kv --copy COPY_FROM_PATH COPY_TO_PATH`

**copy** will copy k/v tree at COPY_FROM_PATH to COPY_TO_PATH.

**NOTE:** In addition of VAULT_ADDR and VAULT_TOKEN environment variable, the two following are needed

* `VAULT_TARGET_ADDR` : Vault URL which will be the target for the exported key/value store
* `VAULT_TARGET_TOKEN` : Vault token with correct right for `VAULT_TARGET_ADDR`

All secrets under COPY_FROM_PATH on $VAULT_ADDR will be copied to COPY_TO_PATH on $VAULT_TARGET_ADDR. ($VAULT_ADDR and $VAULT_TARGET_ADDR can be identical if you want to duplicate a secret tree)

e.g.

with the following command

`vault-manager kv --copy path/to/tree path/to/new-tree`

The secret `path/to/tree/this/is/secret` will be copied at `path/to/new-tree/this/is/secret`

**WARNING:** All secrets already existing on $VAULT_TARGET_ADDR will be overwritten

**NOTE:** Secrets already existing on $VAULT_TARGET_ADDR but not existing on $VAULT_ADDR will not be deleted

#### delete

`vault-manager kv --delete PATH_TO_DELETE`

**delete** will delete all secrets at and under PATH_TO_DELETE on $VAULT_ADDR

**WARNING:** All secrets at and under PATH_TO_DELETE will be deleted and it will not be possible to recover them

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
