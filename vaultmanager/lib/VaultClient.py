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