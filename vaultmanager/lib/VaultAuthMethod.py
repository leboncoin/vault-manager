import hashlib


class VaultAuthMethod:
    """
    Vault authentication method container
    """
    type = None
    path = None
    description = None
    tuning = None
    auth_config = None

    def __init__(self, type, path, description, tuning=None, auth_config=None):
        """
        Instanciate class

        :param type: Authentication type
        :type type: str
        :param path: Authentication mount point
        :type path: str
        :param description: Authentication description
        :type description: str
        :param tuning: Authentication tuning
        :type tuning: dict
        :param auth_config: Authentification specific configuration
        :type auth_config: dict
        """
        self.type = type
        self.path = path.replace("/", "")
        self.description = (description if description else "")
        self.tuning = {}
        for elem in tuning:
            if tuning[elem] != "":
                self.tuning[elem] = tuning[elem]
        self.auth_config = auth_config

    def get_unique_id(self):
        """
        Return a unique hash by auth method only using the type and path

        :return: str
        """
        unique_str = str(self.type + self.path)
        sha256_hash = hashlib.sha256(unique_str.encode()).hexdigest()
        return sha256_hash

    def get_tuning_hash(self):
        """
        Return a unique ID per tuning configuraiton

        :return: str
        """
        conf_str = self.description + str(self.tuning)
        sha256_hash = hashlib.sha256(conf_str.encode()).hexdigest()
        return sha256_hash

    def __eq__(self, other):
        return self.get_unique_id() == other.get_unique_id()

    def __repr__(self):
        return ("Path: %s - Type: %s - Desc: %s - Options: %s - Hash : %s" %
                (self.path, self.type, self.description, str(self.tuning),
                 self.get_unique_id()))
