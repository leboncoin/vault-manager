import logging


class AuthMethodTemplate:
    """
    Template configuration specific class
    """
    logger = None
    mount_point = None
    auth_config = None

    def __init__(self, base_logger, mount_point, auth_config):
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

    def auth_method_configuration(self):
        """
        Entry point
        """
        self.logger.debug("Setting up configuration for " + self.mount_point)
