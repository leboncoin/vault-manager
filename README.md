# vault-manager

vault-manager is a CLI which allows to keep all your Hashicorp Vault configuration in a directory.

## How does it works

vault-manager is a CLI which use modules to interact with Vault.
Each module is and should be designed to interact woth a Vault part ('policies' module allows to manage policies, 'auth' module allows to manage authentication methods etc...)

## Installation and usage

### Using pip

#### Prerequisite

vault-manager has been developed using python 3.6.5 and works fine with this version.
Some modules may not work using python 2.

Be sure there's a pypi source containing vaultmanager setup on your computer

#### Installation

```bash
$> pip install vaultmanager
```

**And you're now ready to go !**

### From source

#### Prerequisite

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
pip install dist/vaultmanager-2.0.0.tar.gz
```

**And you're now ready to go !**

## How to use it

Once the vaultmanager installed, you can now use the following command

```bash
$> vault-manager -h
usage: vault-manager [-h] [-V] [-v] [-d] [-s] [--vault-addr [VAULT_ADDR]]
                     [--vault-target-addr [VAULT_TARGET_ADDR]] [--vault-token]
                     [--vault-target-token] [--vault-config [VAULT_CONFIG]]
                     {ldap,policies,kv} ...

Vault configuration manager

positional arguments:
  {ldap,policies,kv}
    ldap                ldap management
    policies            policies management
    kv                  kv management

optional arguments:
  -h, --help            show this help message and exit
  -V, --version         display version and exit
  -v, --verbose         enable verbose mode
  -d, --dry-run         run in dry mode: No API calls
  -s, --skip-tls        disable TLS verification
  --vault-addr [VAULT_ADDR]
                        Vault address (https://<URL>:<PORT>)
  --vault-target-addr [VAULT_TARGET_ADDR]
                        Vault target address (https://<URL>:<PORT>)
  --vault-token         Prompt for Vault token
  --vault-target-token  Prompt for Vault target token
  --vault-config [VAULT_CONFIG]
                        Specify location of vault_config folder
```

You can print the help for each module by typing

```bash
vault-manager <module> -h
```

Each module can be run with `--dry-run`, `--verbose` or `--skip-tls` args

Argument -v, --verbose is quantitative:
* no `-v` flag will produce a standard output with an `INFO` log level
* `-v` flag enhance the log output but stays in `INFO` level
* `-vv` flag enhance the log output comparing to `-v` and change the log level to `DEBUG` 

e.g.

```bash
$> vault-manager -vv -d -s ldap --list-groups
```

## Modules

There's 3 vaultmanager modules:
* **kv**: K/V store management. Contains different operations on the Vault K/V store
* **ldap**: LDAP management. Allows to create groups/users Vault policies from a LDAP and configure them into Vault
* **policies**: Vault policies management. Allows to push/pull policies created with `ldap` module from/to Vault instance

For each **Needed arguments** sections below, arguments can be specified in two ways:
* as a command line argument
* as an environment variable

Here is the correspondence table:

| Command line argument | Environment variable |
|-----------------------|----------------------|
| --vault-addr          | VAULT_ADDR           |
| --vault-target-addr   | VAULT_TARGET_ADDR    |
| --vault-token         | VAULT_TOKEN          |
| --vault-target-token  | VAULT_TARGET_TOKEN   |
| --vault-config        | VAULT_CONFIG         |

If `--vault-token` or `--vault-target` are present, you will be prompted for tokens

## kv

**kv** modules allows to perform actions on the key/value store

```bash
$> vault-manager kv -h
usage: vault-manager kv [-h] [--copy-path COPY_FROM_PATH COPY_TO_PATH]
                        [--copy-secret SECRET_TO_COPY SECRET_TARGET]
                        [--delete PATHS_TO_DELETE [PATHS_TO_DELETE ...]]
                        [--count SECRET_PATHS [SECRET_PATHS ...]]
                        [--find-duplicates SECRET_PATHS [SECRET_PATHS ...]]
                        [--secrets-tree SECRET_PATHS [SECRET_PATHS ...]]
                        [-e SECRET_PATHS [SECRET_PATHS ...]]
                        [--generate-tree SECRET_PATHS [SECRET_PATHS ...]]
                        [--depth [DEPTH]]

optional arguments:
  -h, --help            show this help message and exit
  --copy-path COPY_FROM_PATH COPY_TO_PATH
                        copy kv store from specified path COPY_FROM_PATH from
                        $VAULT_ADDR instance to $VAULT_TARGET_ADDR at path
                        COPY_TO_PATH. $VAULT_TOKEN is used for $VAULT_ADDR and
                        $VAULT_TARGET_TOKEN is used for $VAULT_TARGET_ADDR
  --copy-secret SECRET_TO_COPY SECRET_TARGET
                        copy one secret from $VAULT_ADDR instance at
                        SECRET_TO_COPY to $VAULT_TARGET_ADDR at SECRET_TARGET
  --delete PATHS_TO_DELETE [PATHS_TO_DELETE ...]
                        delete PATH_TO_DELETE and all secrets under it from
                        $VAULT_ADDR instance. $VAULT_TOKEN is used for
                        $VAULT_ADDR
  --count SECRET_PATHS [SECRET_PATHS ...]
                        count all secrets on $VAULT_ADDR instance under
                        SECRET_PATHS
  --find-duplicates SECRET_PATHS [SECRET_PATHS ...]
                        search and display duplicates on $VAULT_ADDR instance
                        under SECRET_PATHS
  --secrets-tree SECRET_PATHS [SECRET_PATHS ...]
                        display all secrets tree (path/to/secret:key) on
                        $VAULT_ADDR instance under SECRET_PATHS
  -e SECRET_PATHS [SECRET_PATHS ...], --exclude SECRET_PATHS [SECRET_PATHS ...]
                        paths to excludes from count, find-duplicates or
                        secrets-tree
  --generate-tree SECRET_PATHS [SECRET_PATHS ...]
                        paths under which will be generated a random secrets
                        tree
  --depth [DEPTH]       depth of tree generated by generate-tree
```

### Configuration file

There is no configuration file needed by this module

#### --copy-path

`vault-manager kv --copy-path COPY_FROM_PATH COPY_TO_PATH`

##### Arguments needed

* vault-addr
* vault-target-addr
* vault-token
* vault-target-token

**copy-path** will copy k/v tree at COPY_FROM_PATH to COPY_TO_PATH.

**copy-path** should be used only to copy secrets folders. To copy a single secret instead, use **copy-secret**

All secrets under `COPY_FROM_PATH` on `vault-addr` will be copied to `COPY_TO_PATH` on `vault-target-addr`. (`vault-addr` and `vault-target-addr` can be identical if you want to duplicate a secret tree on the same Vault instance)

##### Example

with the following command

`vault-manager kv --copy-path path/to/tree path/to/new-tree`

The secret `path/to/tree/this/is/secret` will be copied at `path/to/new-tree/this/is/secret`

**WARNING:** All secrets already existing on `vault-target-addr` will be overwritten

**NOTE:** Secrets already existing on `vault-target-addr` but not existing on `vault-addr` will not be deleted

#### --copy-secret

`vault-manager kv --copy-secret SECRET_TO_COPY SECRET_TARGET`

##### Arguments needed

* vault-addr
* vault-target-addr
* vault-token
* vault-target-token

##### Description

**copy-secret** will copy a single secret at `SECRET_TO_COPY` to `SECRET_TARGET`.

**copy-secret** should be used only to copy single secrets. To copy a path instead, use `--copy-path`

All secrets under `COPY_FROM_PATH` on `vault-addr` will be copied to `COPY_TO_PATH` on `vault-target-addr`. (`vault-addr` and `vault-target-addr` can be identical if you want to duplicate a secret tree on the same Vault instance)

##### Example

with the following command

`vault-manager kv --copy-secret this/is/secret this/is/new-secret`

The secret `this/is/secret` will be copied at `this/is/new-secret`

**WARNING:** The secret already existing on `vault-target-addr` will be overwritten

#### --delete

`vault-manager kv --delete PATHS_TO_DELETE [PATHS_TO_DELETE ...]`

##### Arguments needed

* vault-addr
* vault-target-addr
* vault-token
* vault-target-token

##### Description

**delete** will delete all secrets at and under each path of `PATHS_TO_DELETE` on `vault-addr`

**WARNING:** All secrets at and under `PATH_TO_DELETE` will be deleted and it will not be possible to recover them

#### --count

`vault-manager kv --count SECRET_PATHS [SECRET_PATHS ...] --exclude SECRET_PATHS [SECRET_PATHS ...]`

##### Arguments needed

* vault-addr
* vault-token

##### Description

This command will count all secrets under each path of `SECRET_PATHS`

If one or several path(s) is/are specified after `--exclude`, these paths will be excluded from the count

##### Example
 
```bash
$> vault-manager kv --count services apps
{
    "services": {
        "secrets_count": 5,
        "values_count": 6
    },
    "apps": {
        "secrets_count": 5,
        "values_count": 8
    }
}
```

#### --find-duplicates

`vault-manager kv --find-duplicates SECRET_PATHS [SECRET_PATHS ...] --exclude SECRET_PATHS [SECRET_PATHS ...]`

##### Arguments needed

* vault-addr
* vault-token

##### Description

This command will look for each secret value under `SECRET_PATHS` and will try to find a duplicated value of this value 

The output is a dictionary of duplicate's groups

##### Example

```bash
$> vault-manager kv --find-duplicates services apps
{
    "0": [
        "apps/path/to/secret:key",
        "services/another/path/anothersecret:otherkey"
    ],
    "1": [
        "apps/hello/credentials:username",
        "apps/accounts/user1:password"
    ]
}
```

This means:
 * The value of the secret `apps/path/to/secret` at key `key` is the same than the secret `services/another/path/anothersecret` at the key `otherkey`
 * The value of the secret `apps/hello/credentials` at key `username` is the same than the secret `apps/accounts/user1` at the key `password`


#### --secrets-tree

`vault-manager kv --secrets-tree SECRET_PATHS [SECRET_PATHS ...] --exclude SECRET_PATHS [SECRET_PATHS ...]`

##### Arguments needed

* vault-addr
* vault-token

##### Description

This command will display all secrets paths under `SECRET_PATHS`

The output is a dictionary of lists grouped by root path

##### Example

```bash
$> vault-manager kv --secrets-tree services apps
{
    "services": [
        "services/prod/ldap/accounts/svc-vault",
        "services/tree/alsoin/newpath/newsecret",
        "services/tree/alsoin/services/secret1",
        "services/tree/directsecret",
        "services/tree/in/services/secret"
    ],
    "apps": [
        "apps/app1/credentials",
        "apps/credentials",
        "apps/app2/username"
    ]
}
```

#### --generate-tree

`vault-manager kv --generate-tree SECRET_PATHS [SECRET_PATHS ...] --depth [DEPTH]`

##### Arguments needed

* vault-addr
* vault-token

##### Description

This command will generate a random secrets tree under `SECRET_PATHS` using words in `/usr/share/dict/words`

**WARNING**: This command can take a long time if you specify a high depth (>4)

##### Example

```bash
$> vault-manager kv --generate-tree apps --depth 2
Will create 1 secrets and 2 folders under 'apps'
Will create 5 secrets and 0 folders under 'apps/Laburnum'
Will create 5 secrets and 0 folders under 'apps/valeric'
```

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

**WARNING:** The env var specified in `ldap.yml` under `ldap.password` must be set.
It should be the password the LDAP account specified in `ldap.yml` under `ldap.username`.   

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
