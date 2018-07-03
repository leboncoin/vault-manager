import logging
import hashlib


class AuthMethodLDAP:
    """
    LDAP configuration specific class
    """
    logger = None
    mount_point = None
    distant_auth_config = None
    vault_client = None
    distant_conf = None
    local_conf = None

    def __init__(self, base_logger, mount_point, auth_config, vault_client):
        """
        :param base_logger: main class name
        :type base_logger: string
        :param mount_point: auth method mount point
        :type mount_point: str
        :param auth_config: auth method specific configuration
        :type auth_config: dict
        """
        self.logger = logging.getLogger(base_logger + "." +
                                        self.__class__.__name__)
        self.mount_point = mount_point
        self.local_conf = auth_config
        self.vault_client = vault_client

    def get_hash(self, string):
        """
        Return a hash of specified string

        :param string: string to hash
        :type string: str

        :return: str
        """
        string = str(string)
        self.logger.debug("Hashing " + string)
        sha256_hash = hashlib.sha256(string.encode()).hexdigest()
        self.logger.debug("Hashed string: " + sha256_hash)
        return sha256_hash

    def get_ldap_configuration(self):
        """
        Fetch the distant authentification configuration
        """
        self.logger.debug("Fetching distant auth configuration")
        ldap_conf = {}
        raw = self.vault_client.read('/auth/ldap/config')
        for key in raw:
            if raw[key] != '':
                ldap_conf[key] = raw[key]
        self.logger.debug("Distant configuration: " + str(ldap_conf))
        self.distant_conf = ldap_conf

    def push_local_conf(self):
        """
        Push local auth conf to Vault instance
        """
        self.logger.debug("Pushing local auth conf")
        to_hide_fields = []
        for key in self.local_conf:
            filled_secret = self.vault_client.read_string_with_secret(
                self.local_conf[key]
            )
            if self.local_conf[key] != filled_secret:
                self.local_conf[key] = filled_secret
                to_hide_fields.append(key)
        self.vault_client.write("auth/" + self.mount_point + "/config",
                                self.local_conf, to_hide_fields)

    def auth_method_configuration(self):
        """
        Entry point
        """
        self.logger.debug("Setting up configuration for " + self.mount_point)
        self.logger.debug("Local configuration: " + str(self.local_conf))
        self.get_ldap_configuration()
        if self.get_hash(self.local_conf) != self.get_hash(self.distant_conf):
            self.push_local_conf()
        else:
            self.logger.info("No auth conf change to push")
