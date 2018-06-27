import os
import logging
import getpass
import hvac


class VaultClient:
    """
    Class to handle interaction with Vault instance
    """
    logger = None
    vault_client = None

    def __init__(self, base_logger):
        """
        :param base_logger: main class name
        :type base_logger: string
        """
        self.logger = logging.getLogger(base_logger + "." +
                                        self.__class__.__name__)
        self.logger.debug("Instanciating VaultClient class")
        self.fetch_api_address()

    def fetch_api_address(self):
        """
        Fetch the Vault API address and instanciate hvac client
        """
        if "VAULT_ADDR" in os.environ:
            self.logger.debug("'VAULT_ADDR' found in env")
            vault_address = os.environ["VAULT_ADDR"]
        else:
            self.logger.debug("'VAULT_ADDR' not found in env. Asking for a token")
            vault_address = input("Vault address to use "\
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

    def is_authenticated(self):
        """
        Check if authenticated against Vault

        :return: bool
        """
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
        listed = self.vault_client.list(path)
        if listed:
            return listed["data"]
        return {}

    def write(self, path, params):
        """
        Write at specified path

        :param path: Path to write
        :type path: str

        :return: dict
        """
        self.logger.debug("Writing " + str(params) + " at " + path)
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
        deleted = self.vault_client.delete(path)
        return deleted

    def policy_list(self):
        """
        List all policies found in Vault

        :return: policies list
        """
        self.logger.debug("Fetching list of existing policies")
        self.logger.debug("Policies root and default will not be returned")
        policies = self.vault_client.list_policies()
        policies = [pol for pol in policies if pol not in ["root", "default"]]
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
        self.logger.debug("Setting policy " + policy_name + " - content: \n" + policy_content)
        self.vault_client.set_policy(policy_name, policy_content)

    def policy_delete(self, policy_name):
        """
        Delete a policy from Vault

        :param policy_name:
        :type policy_name: str
        """
        self.logger.debug("Deleting policy " + policy_name)
        self.vault_client.delete_policy(policy_name)

    def policy_get(self, policy_name):
        """
        Get a policy

        :param policy_name: name of the policy
        :type policy_name: str
        :return: string
        """
        self.logger.debug("Get policy " + policy_name)
        policy_content = self.vault_client.get_policy(policy_name)
        return policy_content

    def read_secret(self, secret_path):
        """
        Read and return a secret

        :param secret_path: secret path
        :type secret_path: str
        :return: str
        """
        self.logger.debug("Reading secret '" + secret_path + "'")
        secret = self.vault_client.read(secret_path)
        return secret

    def audit_list(self):
        """
        List and return audit devices

        :return: dict
        """
        self.logger.debug("Listing audit devices")
        raw = self.vault_client.list_audit_backends()
        return raw["data"]

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
        self.vault_client.disable_audit_backend(path)

    def auth_list(self):
        """
        list and return auth methods

        :return: dict
        """
        self.logger.debug("Listing auth methods")
        raw = self.vault_client.list_auth_backends()
        return raw["data"]

    def auth_enable(self, auth_type, path, description, config):
        """
        Enable a new audit device

        :param auth_type: auth method type
        :type auth_type: str
        :param path: mounting point
        :type path: str
        :param description: auth method description
        :type description: str
        :param config: options needed by the auth method
        :type config: dict
        """
        self.logger.debug("Enabling '" + auth_type + "' auth method - "
                          + str(config))
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
        self.logger.debug("Tuning auth method: " + str(mount_point))
        self.logger.debug("default_lease_ttl: " + str(default_lease_ttl))
        self.logger.debug("max_lease_ttl: " + str(max_lease_ttl))
        self.logger.debug("description: " + str(description))
        self.logger.debug("audit_non_hmac_request_keys: " + str(audit_non_hmac_request_keys))
        self.logger.debug("audit_non_hmac_response_keys: " + str(audit_non_hmac_response_keys))
        self.logger.debug("listing_visibility: " + str(listing_visibility))
        self.logger.debug("passthrough_request_headers: " + str(passthrough_request_headers))
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
