import os
import logging
import getpass
import hvac
import re


class VaultClient:
    """
    Class to handle interaction with Vault instance
    """
    logger = None
    vault_client = None
    dry = None

    def __init__(self, base_logger, dry):
        """
        :param base_logger: main class name
        :type base_logger: string
        :param dry: is running in dry run
        :type dry: bool
        """
        self.logger = logging.getLogger(base_logger + "." +
                                        self.__class__.__name__)
        self.logger.debug("Dry run: " + str(dry))
        self.dry = dry
        self.logger.debug("Instantiating VaultClient class")
        self.fetch_api_address()

    """
    API call methods
    """
    def is_authenticated(self):
        """
        Check if authenticated against Vault

        :return: bool
        """
        if self.dry_run():
            return True
        if self.vault_client.is_authenticated():
            self.logger.debug("Client is authenticated")
        else:
            self.logger.debug("Client is NOT authenticated")
        return self.vault_client.is_authenticated()

    def read(self, path):
        """
        Read specified path

        :param path: Path to read
        :type path: str

        :return: dict
        """
        self.logger.debug("Reading at " + path)
        read = None
        if not self.dry_run():
            read = self.vault_client.read(path)
        if read:
            return read["data"]
        return {}

    def list(self, path):
        """
        List specified path

        :param path: Path to list
        :type path: str

        :return: dict
        """
        self.logger.debug("Listing at " + path)
        listed = None
        if not self.dry_run():
            listed = self.vault_client.list(path)
        if listed:
            return listed["data"]
        return {}

    def write(self, path, params, fields_to_hide=None):
        """
        Write at specified path

        :param path: Path to write
        :type path: str
        :param params: Key/Value to write
        :type params: dict
        :param fields_to_hide: Fields of Key/Value dict to hide in log
        :type fields_to_hide: list

        :return: dict
        """
        if not fields_to_hide:
            self.logger.debug("Writing " + str(params) + " at " + path)
        else:
            to_display = {}
            for key in params:
                if key not in fields_to_hide:
                    to_display[key] = params[key]
                else:
                    to_display[key] = "HIDDEN"
            self.logger.debug("Writing " + str(to_display) + " at " + path)
        written = None
        if not self.dry_run():
            written = self.vault_client.write(path, **params)
        return written

    def delete(self, path):
        """
        Delete specified path

        :param path: Path to delete
        :type path: str

        :return: dict
        """
        self.logger.debug("Deleting at " + path)
        deleted = None
        if not self.dry_run():
            deleted = self.vault_client.delete(path)
        return deleted

    def policy_list(self):
        """
        List all policies found in Vault

        :return: policies list
        """
        self.logger.debug("Fetching list of existing policies")
        self.logger.debug("Policies root and default will not be returned")
        policies = []
        if not self.dry_run():
            policies = self.vault_client.list_policies()
            policies = [pol for pol in policies if
                        pol not in ["root", "default"]]
        self.logger.debug(str(len(policies)) + " policies found")
        return policies

    def policy_set(self, policy_name, policy_content):
        """
        Set a policy in Vault

        :param policy_name: name of the policy
        :type policy_name: str
        :param policy_content: content of the policy
        :type policy_content: str
        """
        self.logger.debug("Setting policy %s - content: \n%s" %
                          (policy_name, policy_content))
        if not self.dry_run():
            self.vault_client.set_policy(policy_name, policy_content)

    def policy_delete(self, policy_name):
        """
        Delete a policy from Vault

        :param policy_name:
        :type policy_name: str
        """
        self.logger.debug("Deleting policy " + policy_name)
        if not self.dry_run():
            self.vault_client.delete_policy(policy_name)

    def policy_get(self, policy_name):
        """
        Get a policy

        :param policy_name: name of the policy
        :type policy_name: str

        :return: string
        """
        self.logger.debug("Get policy " + policy_name)
        policy_content = "POLICY_CONTENT"
        if not self.dry_run():
            policy_content = self.vault_client.get_policy(policy_name)
        return policy_content

    def read_secret(self, secret_path):
        """
        Read and return a secret

        :param secret_path: secret path
        :type secret_path: str

        :return: dict
        """
        self.logger.debug("Reading secret '" + secret_path + "'")
        secret = {"KEY": "SECRET"}
        if not self.dry_run():
            secret = self.vault_client.read(secret_path)
            return secret["data"]
        return secret

    def audit_list(self):
        """
        List and return audit devices

        :return: dict
        """
        self.logger.debug("Listing audit devices")
        if not self.dry_run():
            raw = self.vault_client.list_audit_backends()
            return raw["data"]
        return {}

    def audit_enable(self, audit_type, path, description, options):
        """
        Enable a new audit device

        :param audit_type: audit device type
        :type audit_type: str
        :param path: mounting point
        :type path: str
        :param description: audit device description
        :type description: str
        :param options: options needed by the audit device type
        :type options: dict
        """
        self.logger.debug("Enabling '" + audit_type + "' audit device at " +
                          path + " - " + str(options))
        if not self.dry_run():
            self.vault_client.enable_audit_backend(
                backend_type=audit_type,
                description=description,
                options=options,
                name=path
            )

    def audit_disable(self, path):
        """
        Disable an ausit device

        :param path: mounting point
        :type path: str
        """
        self.logger.debug("Disabling audit device '" + path + "'")
        if not self.dry_run():
            self.vault_client.disable_audit_backend(path)

    def auth_list(self):
        """
        list and return auth methods

        :return: dict
        """
        self.logger.debug("Listing auth methods")
        if not self.dry_run():
            raw = self.vault_client.list_auth_backends()
            return raw["data"]
        return {}

    def auth_enable(self, auth_type, path, description):
        """
        Enable a new audit device

        :param auth_type: auth method type
        :type auth_type: str
        :param path: mounting point
        :type path: str
        :param description: auth method description
        :type description: str
        """
        self.logger.debug("Enabling '" + auth_type + "' auth method")
        if not self.dry_run():
            self.vault_client.enable_auth_backend(
                backend_type=auth_type,
                mount_point=path,
                description=description
            )

    def auth_disable(self, path):
        """
        Disable an auth method

        :param path: mounting point
        :type path: str
        """
        self.logger.debug("Disabling auth method '" + path + "'")
        if not self.dry_run():
            self.vault_client.disable_auth_backend(path)

    def auth_tune(self, mount_point, default_lease_ttl, max_lease_ttl,
                  description=None, audit_non_hmac_request_keys=None,
                  audit_non_hmac_response_keys=None, listing_visibility=None,
                  passthrough_request_headers=None):
        """

        :param mount_point: Auth method mount point
        :param default_lease_ttl: Default lease TTL
        :param max_lease_ttl:  Max lease TTL
        :param description: Description
        :param audit_non_hmac_request_keys:
        :param audit_non_hmac_response_keys:
        :param listing_visibility:
        :param passthrough_request_headers:
        """
        self.logger.debug("Tuning auth method: %s" % str(mount_point))
        self.logger.debug("default_lease_ttl: %s" % str(default_lease_ttl))
        self.logger.debug("max_lease_ttl: %s" % str(max_lease_ttl))
        self.logger.debug("description: %s" % str(description))
        self.logger.debug("audit_non_hmac_request_keys: %s" %
                          str(audit_non_hmac_request_keys))
        self.logger.debug("audit_non_hmac_response_keys: %s" %
                          str(audit_non_hmac_response_keys))
        self.logger.debug("listing_visibility: %s" %
                          str(listing_visibility))
        self.logger.debug("passthrough_request_headers: %s" %
                          str(passthrough_request_headers))
        if not self.dry_run():
            self.vault_client.tune_auth_backend(
                backend_type=None,
                mount_point=mount_point,
                default_lease_ttl=default_lease_ttl,
                max_lease_ttl=max_lease_ttl,
                description=description,
                audit_non_hmac_request_keys=audit_non_hmac_request_keys,
                audit_non_hmac_response_keys=audit_non_hmac_response_keys,
                listing_visibility=listing_visibility,
                passthrough_request_headers=passthrough_request_headers
            )

    def auth_approle_list(self, mount_point):
        """
        Fetch the list of roles at mount point

        :param mount_point: approle auth mount point
        :type mount_point: str

        :return: dict
        """
        self.logger.debug("Listing roles at " + mount_point)
        if not self.dry_run():
            try:
                raw_roles = self.vault_client.list_roles(mount_point)
            except hvac.exceptions.InvalidPath:
                return []
            return raw_roles['data']['keys']
        return {}

    def auth_approle_get(self, role_name, mount_point):
        """
        Get role configuration

        :param role_name: Role name
        :type role_name: str
        :param mount_point: approle mount point
        :type mount_point: str

        :return: dict
        """
        self.logger.debug("Get role configuration for %s at %s" %
                          (role_name, mount_point))
        if not self.dry_run():
            raw_role = self.vault_client.get_role(role_name, mount_point)
            return raw_role['data']
        return {
            'bind_secret_id': True,
            'bound_cidr_list': [],
            'local_secret_ids': False,
            'period': 0,
            'policies': ['policy'],
            'secret_id_num_uses': 0,
            'secret_id_ttl': 0,
            'token_max_ttl': 0,
            'token_num_uses': 0,
            'token_ttl': 0
        }

    def auth_approle_create(self, role_name, role_conf, mount_point):
        """
        Create a new role at mount point

        :param role_name: Role name
        :type role_name: str
        :param role_conf: Role parameters
        :type role_conf: dict
        :param mount_point: approle mount point
        :type mount_point: str
        """
        self.logger.debug("Adding role %s/role/%s: %s" %
                          (mount_point, role_name, str(role_conf)))
        if not self.dry_run():
            self.vault_client.create_role(
                role_name,
                mount_point,
                **role_conf
            )

    def auth_approle_delete(self, role_name, mount_point):
        """
        Delete a role at mount point

        :param role_name: Role name
        :type role_name: str
        :param mount_point: approle mount point
        :type mount_point: str
        """
        self.logger.debug("Deleting role %s/role/%s" % (mount_point, role_name))
        if not self.dry_run():
            self.vault_client.delete_role(role_name, mount_point)

    def auth_approle_tune(self, role_name, role_conf, mount_point):
        """
        Create a new role at mount point

        :param role_name: Role name
        :type role_name: str
        :param role_conf: Role parameters
        :type role_conf: dict
        :param mount_point: approle mount point
        :type mount_point: str
        """
        self.logger.debug("Tuning role %s/role/%s: %s" %
                          (mount_point, role_name, str(role_conf)))
        if not self.dry_run():
            self.write("auth/" + mount_point + "/role/" + role_name, role_conf)

    def secret_list(self):
        """
        list and return secrets engines

        :return: dict
        """
        self.logger.debug("Listing secrets engines")
        secrets_engines = {}
        if not self.dry_run():
            raw = self.vault_client.list_secret_backends()
            for key in raw["data"]:
                if key not in ["cubbyhole/", "identity/", "sys/", "identity/"]:
                    secrets_engines[key] = raw["data"][key]
            return secrets_engines
        return secrets_engines

    def secret_enable(self, secret_type, path, description):
        """
        Enable a new secret engine

        :param secret_type: secret engine type
        :type secret_type: str
        :param path: mounting point
        :type path: str
        :param description: secret engine description
        :type description: str
        """
        self.logger.debug("Enabling '" + secret_type + "' secret engine")
        if not self.dry_run():
            self.vault_client.enable_secret_backend(
                backend_type=secret_type,
                mount_point=path,
                description=description
            )

    def secret_disable(self, path):
        """
        Disable an secret engine

        :param path: mounting point
        :type path: str
        """
        self.logger.debug("Disabling secret engine '" + path + "'")
        if not self.dry_run():
            self.vault_client.disable_secret_backend(path)

    def secret_tune(self, mount_point, default_lease_ttl, max_lease_ttl,
                    description=None, audit_non_hmac_request_keys=None,
                    audit_non_hmac_response_keys=None, listing_visibility=None,
                    passthrough_request_headers=None):
        """

        :param mount_point: Auth method mount point
        :param default_lease_ttl: Default lease TTL
        :param max_lease_ttl:  Max lease TTL
        :param description: Description
        :param audit_non_hmac_request_keys:
        :param audit_non_hmac_response_keys:
        :param listing_visibility:
        :param passthrough_request_headers:
        """
        self.logger.debug("Tuning auth method: %s" % str(mount_point))
        self.logger.debug("default_lease_ttl: %s" % str(default_lease_ttl))
        self.logger.debug("max_lease_ttl: %s" % str(max_lease_ttl))
        self.logger.debug("description: %s" % str(description))
        self.logger.debug("audit_non_hmac_request_keys: %s" %
                          str(audit_non_hmac_request_keys))
        self.logger.debug("audit_non_hmac_response_keys: %s" %
                          str(audit_non_hmac_response_keys))
        self.logger.debug("listing_ visibility: %s" %
                          str(listing_visibility))
        self.logger.debug("passthrough_request_headers: %s" %
                          str(passthrough_request_headers))
        # TODO: To uncomment when pull request accepted
        if not self.dry_run():
            self.vault_client.tune_secret_backend(
                backend_type=None,
                mount_point=mount_point,
                default_lease_ttl=default_lease_ttl,
                max_lease_ttl=max_lease_ttl
                # description=description,
                # audit_non_hmac_request_keys=audit_non_hmac_request_keys,
                # audit_non_hmac_response_keys=audit_non_hmac_response_keys,
                # listing_visibility=listing_visibility,
                # passthrough_request_headers=passthrough_request_headers
            )

    """
    Other methods
    """
    def dry_run(self):
        """
        Log entry if dry vault_client call
        """
        if self.dry:
            self.logger.debug("DRY CALL to vault api")
            return True
        return False

    def fetch_api_address(self):
        """
        Fetch the Vault API address and instanciate hvac client
        """
        if "VAULT_ADDR" in os.environ:
            self.logger.debug("'VAULT_ADDR' found in env")
            vault_address = os.environ["VAULT_ADDR"]
        else:
            self.logger.debug("'VAULT_ADDR' not in env. Asking for a token")
            vault_address = input("Vault address to use "
                                  "(http://vault_address:vault_port): ")
        self.logger.debug("Vault address to be used: " + vault_address)
        self.vault_client = hvac.Client(url=vault_address)

    def authenticate(self):
        """
        Vault authentication
        """
        self.logger.debug("Starting token authentication")
        if "VAULT_TOKEN" in os.environ:
            self.vault_client.token = os.environ["VAULT_TOKEN"]
        else:
            self.vault_client.token = getpass.getpass(
                "Please enter token with correct rights: ")
        self.is_authenticated()

    def read_string_with_secret(self, string):
        """
        If string received contains VAULT{{path/to/secret}},
        return secret found at path/to/secret.
        If pattern not found, return not changed string

        :param string: string in which to look for secret path
        :type string: str

        :return: str
        """
        if not string or not isinstance(string, str):
            return string
        match = re.findall("VAULT{{(.+):(.+)}}", string)
        if len(match) == 1:
            self.logger.debug("Secret found in: %s:%s. Looking in Vault" %
                              (match[0][0], match[0][1]))
            if not self.dry_run():
                return self.read_secret(match[0][0])[match[0][1]]
            return self.read_secret(match[0][0])
        return string

    def get_secrets_tree(self, path):
        """
        Get the secrets tree for the given path

        :param path: path to check
        :type path: str

        :return: the list of all secrets
        """
        self.logger.debug("Finding tree in " + path)
        tree = []
        tree += self.get_secrets_tree_recursive(path)
        return tree

    def get_secrets_tree_recursive(self, path):
        """
        Recursively browse a path and find secrets

        :param path: path to browse
        :type path:str

        :return:list
        """
        secrets = []
        if len(self.list(path)):
            for p in self.list(path)['keys']:
                if p.endswith("/"):
                    secrets += self.get_secrets_tree_recursive(path + "/" + p)
                else:
                    secrets.append(path + "/" + p)
        return secrets