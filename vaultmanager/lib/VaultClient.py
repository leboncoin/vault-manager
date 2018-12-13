import os
import logging
import hvac
import re


class VaultClient:
    """
    Class to handle interaction with Vault instance
    """
    logger = None
    vault_client = None
    dry = None
    skip_tls = None

    def __init__(self, base_logger, dry=False, vault_addr=None, skip_tls=False):
        """
        :param base_logger: main class name
        :type base_logger: string
        :param dry: is running in dry run
        :type dry: bool
        :param vault_addr: vault address which will overload env var VAULT_ADDR
        :type vault_addr :str
        :param skip_tls: skipping TLS verification
        :type skip_tls: bool
        """
        self.logger = logging.getLogger(base_logger + "." +
                                        self.__class__.__name__)
        self.logger.debug("Dry run: " + str(dry))
        self.dry = dry
        self.logger.debug("Skip TLS: " + str(skip_tls))
        self.skip_tls = skip_tls
        self.logger.debug("Instantiating VaultClient class")
        self.logger.debug("Vault address to be used: " + vault_addr)
        self.vault_client = hvac.Client(
            url=vault_addr,
            verify=(not self.skip_tls)
        )

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

    def write(self, path, params, fields_to_hide=None, hide_all=None):
        """
        Write at specified path

        :param path: Path to write
        :type path: str
        :param params: Key/Value to write
        :type params: dict
        :param fields_to_hide: Fields of Key/Value dict to hide in log
        :type fields_to_hide: list
        :param hide_all: Hide key and value in log
        :type hide_all: bool

        :return: dict
        """
        if not fields_to_hide and not hide_all:
            self.logger.debug("Writing " + str(params) + " at " + path)
        elif not hide_all:
            to_display = {}
            for key in params:
                if key not in fields_to_hide:
                    to_display[key] = params[key]
                else:
                    to_display[key] = "HIDDEN"
            self.logger.debug("Writing " + str(to_display) + " at " + path)
        else:
            self.logger.debug("Writing at " + path)
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
            try:
                return secret["data"]
            except TypeError as e:
                self.logger.critical("Cannot read secret at " + secret_path)
                raise e
        return secret

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

    # TODO: should always receive a Vault token
    def authenticate(self, vault_token=None):
        """
        Vault authentication

        :param vault_token: vault token which will overload env var VAULT_TOKEN
        :type vault_token: str
        """
        self.logger.debug("Starting token authentication")
        if vault_token:
            self.vault_client.token = vault_token
        elif "VAULT_TOKEN" in os.environ:
            self.vault_client.token = os.environ["VAULT_TOKEN"]
        else:
            self.logger.error("No Vault token found")
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
        return string

    def read_string_with_env(self, string):
        """
        If string received contains ENV{{env_var_name}},
        return environment variable value.
        If the env var is not found, return string given

        :param string: name of the env var to look for
        :type string: str

        :return: str
        """
        if not string or not isinstance(string, str):
            return string
        match = re.findall("ENV{{(.+)}}", string)
        if len(match) == 1:
            self.logger.debug("Env var found: %s" % match[0])
            if not self.dry_run():
                return os.getenv(match[0], string)
        return string

    def get_secrets_tree(self, path):
        """
        DEPRECATED
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
        DEPRECATED
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
        return [secret.replace("//", "/") for secret in secrets]

    def secrets_tree_list(self, path, path_excluded=[]):
        """
        List all secrets at given path

        :param path: Secrets path to list
        :type path: str
        :param path_excluded: List of path to exclude from list
        :type path_excluded: list
        :return: list
        """
        secrets_list = []
        secrets_list += self.secrets_tree_list_recursive(path, path_excluded)
        return secrets_list

    def secrets_tree_list_recursive(self, path, path_excluded):
        """
        Recursive method associated to secrets_tree_list

        :param path: Secrets path to list
        :type path: str
        :param path_excluded: List of path to exclude from list
        :type path_excluded: list
        """
        secrets = []
        # if path is in in path_excluded we return
        for p in path_excluded:
            if path.startswith(p):
                return []

        # If path is a folder we continue else id it's a secret,
        # we return the secret path
        listed = self.list(path)
        if len(listed):
            listed = listed["keys"]
        else:
            if len(self.read(path)):
                self.logger.debug("'%s' is a secret. Will be deleted" % path)
                return [path]

        if len(listed):
            for p in listed:
                avoid = False
                for t_e in path_excluded:
                    if (path + "/" + p).replace("//", "/").startswith(t_e):
                        avoid = True
                if p.endswith("/") and not avoid:
                    secrets += self.secrets_tree_list_recursive(
                        path + "/" + p, path_excluded
                    )
                elif not avoid:
                    secrets.append(path + "/" + p)
        return [secret.replace("//", "/") for secret in secrets]
