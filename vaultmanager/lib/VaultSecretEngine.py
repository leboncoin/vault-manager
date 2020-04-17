import hashlib


class VaultSecretEngine:
    """
    Vault authentication method container
    """
    type = None
    path = None
    description = None
    tuning = None
    secret_config = None

    def __init__(self, type, path, description, tuning=None, secret_config=None):
        """
        Instanciate class

        :param type: Secret type
        :type type: str
        :param path: Secret mount point
        :type path: str
        :param description: Secret description
        :type description: str
        :param tuning: Secret tuning
        :type tuning: dict
        :param secret_config: Secret specific configuration
        :type secret_config: dict
        """
        self.type = type
        # Remove / at begining or end of path
        if path.startswith("/"):
            path = path[1:]
        if path.endswith("/"):
            path = path[:-1]
        self.path = path
        self.description = (description if description else "")
        self.tuning = dict()
        self.tuning["force_no_cache"] = False
        for elem in tuning:
            if tuning[elem] != "":
                self.tuning[elem] = tuning[elem]
        self.secret_config = secret_config

    def get_unique_id(self):
        """
        Return a unique hash by secret engine only using the type and path

        :return: str
        """
        unique_str = str(self.type + self.path)
        sha256_hash = hashlib.sha256(unique_str.encode()).hexdigest()
        return sha256_hash

    def get_tuning_hash(self):
        """
        Return a unique ID per tuning configuration

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
