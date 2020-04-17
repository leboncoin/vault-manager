import logging


class AuthMethodAppRole:
    """
    Template configuration specific class
    """
    logger = None
    mount_point = None
    auth_config = None
    vault_client = None
    local_approles = None
    distant_approles = None
    auth_config_default = None

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
        self.auth_config = auth_config
        self.vault_client = vault_client
        self.auth_config_default = {
            "bind_secret_id": True,
            "bound_cidr_list": [],
            "local_secret_ids": False,
            "period": 0,
            "policies": [],
            "secret_id_num_uses": 0,
            "secret_id_ttl": 0,
            "token_max_ttl": 0,
            "token_num_uses": 0,
            "token_ttl": 0,
            "secret_id_bound_cidrs": [],
            "token_bound_cidrs": [],
            "enable_local_secret_ids": False,
            "token_type": "",
            "token_explicit_max_ttl": 0,
            "token_period": 0,
            "token_policies": [],
            "token_no_default_policy": False,
        }

    def get_distant_approles(self):
        """
        Fetch the list roles in Vault
        """
        self.logger.debug("Fetching approles from Vault")
        distant_approles = self.vault_client.auth_approle_list(self.mount_point)
        self.logger.debug("Distant approles found: " + str(distant_approles))
        self.distant_approles = {}
        for role in distant_approles:
            raw_approle = self.vault_client.auth_approle_get(role,
                                                             self.mount_point)
            for param in raw_approle:
                if param not in self.auth_config_default or \
                        raw_approle[param] != self.auth_config_default[param]:
                    if role not in self.distant_approles:
                        self.distant_approles[role] = {}
                    self.distant_approles[role][param] = \
                        raw_approle[param]
        self.logger.debug("Distant approles conf found: %s" %
                          str(self.distant_approles))

    def add_roles(self):
        """
        Add roles from conf to Vault
        """
        for role in self.auth_config:
            if role not in self.distant_approles:
                self.logger.info("Adding role '%s' - %s to Vault" %
                                 (role, self.auth_config[role]))
                self.vault_client.auth_approle_create(
                    role, self.auth_config[role], self.mount_point
                )

    def delete_roles(self):
        """
        Delete role from Vault not in conf
        """
        for role in self.distant_approles:
            if role not in self.auth_config:
                self.logger.info("Deleting role '%s' from Vault" % role)
                self.vault_client.auth_approle_delete(role, self.mount_point)

    def tune_roles(self):
        """
        Tuning already existing roles in Vault
        """
        self.logger.debug("Tuning roles")
        for role in self.auth_config:
            if role in self.distant_approles:
                params = {}
                for param in self.distant_approles[role]:
                    if param not in self.auth_config[role]:
                        params[param] = self.auth_config_default[param]
                for param in self.auth_config[role]:
                    if param not in self.distant_approles[role]:
                        params[param] = self.auth_config[role][param]
                    elif isinstance(self.auth_config[role][param], list):
                        if sorted(self.auth_config[role][param]) !=\
                                sorted(self.distant_approles[role][param]):
                            params[param] = self.auth_config[role][param]
                    elif self.auth_config[role][param] !=\
                            self.distant_approles[role][param]:
                        params[param] = self.auth_config[role][param]
                if len(params):
                    self.logger.info("Tuning %s/role/%s with %s" %
                                     (self.mount_point, role, params))
                    self.vault_client.auth_approle_tune(
                        role_name=role,
                        role_conf=params,
                        mount_point=self.mount_point
                    )

    def auth_method_configuration(self):
        """
        Entry point
        """
        self.logger.info("Setting up configuration for " + self.mount_point)
        for role in self.auth_config:
            self.auth_config[role].pop('role_name', None)
        self.logger.debug("Auth configuration: " + str(self.auth_config))
        self.get_distant_approles()
        self.add_roles()
        self.delete_roles()
        self.tune_roles()
