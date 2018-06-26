import os
import logging
import yaml
try:
    from lib.VaultClient import VaultClient
    from lib.VaultAuditDevice import VaultAuditDevice
except ImportError:
    from vaultmanager.lib.VaultClient import VaultClient
    from vaultmanager.lib.VaultAuditDevice import VaultAuditDevice


class VaultManagerAudit:
    logger = None
    base_logger = None
    subparser = None
    parsed_args = None
    arg_parser = None
    module_name = None
    conf = None
    vault_client = None
    distant_audit_devices = None
    local_audit_devices = None

    def __init__(self, base_logger, subparsers):
        """
        :param base_logger: main class name
        :type base_logger: string
        :param subparsers: list of all subparsers
        :type subparsers: argparse.ArgumentParser.add_subparsers()
        """
        self.base_logger = base_logger
        self.logger = logging.getLogger(base_logger + "." + self.__class__.__name__)
        self.logger.debug("Initializing VaultManagerLDAP")
        self.initialize_subparser(subparsers)

    def initialize_subparser(self, subparsers):
        """
        Add the subparser of this specific module to the list of all subparsers

        :param subparsers: list of all subparsers
        :type subparsers: argparse.ArgumentParser.add_subparsers()
        :return:
        """
        self.logger.debug("Initializing subparser")
        self.module_name = self.__class__.__name__.replace("VaultManager", "").lower()
        self.subparser = subparsers.add_parser(self.module_name, help=self.module_name + ' management')
        self.subparser.add_argument("--push", action='store_true',
                                    help="Push audit configuration to Vault")
        self.subparser.set_defaults(module_name=self.module_name)

    def read_configuration(self):
        """
        Read configuration file
        """
        self.logger.debug("Reading configuration")
        with open(os.path.join(os.environ["VAULT_CONFIG"], "audit-devices.yml"),
                  'r') as fd:
            try:
                self.conf = yaml.load(fd)
            except yaml.YAMLError as e:
                self.logger.critical("Impossible to load conf file: " + str(e))
                return False
        self.logger.debug("Read conf: " + str(self.conf))
        return True

    def get_distant_audit_devices(self):
        """
        Fetch distant audit devices
        """
        self.logger.debug("Fetching distant audit devices")
        self.distant_audit_devices = []
        raw = self.vault_client.audit_list()
        for elem in raw:
            self.distant_audit_devices.append(
                VaultAuditDevice(
                    raw[elem]["type"],
                    raw[elem]["path"],
                    raw[elem]["description"],
                    raw[elem]["options"]
                )
            )
        self.logger.debug("Distant audit devices found")
        for elem in self.distant_audit_devices:
            self.logger.debug(elem)

    def get_local_audit_devices(self):
        """
        Fetch local audit devices
        """
        self.logger.debug("Fetching local audit devices")
        self.local_audit_devices = []
        for audit_device in self.conf["audit-devices"]:
            self.local_audit_devices.append(
                VaultAuditDevice(
                    audit_device["type"],
                    audit_device["path"],
                    audit_device["description"],
                    audit_device["options"]
                )
            )
        self.logger.debug("Local audit devices found")
        for elem in self.local_audit_devices:
            self.logger.debug(elem)

    def disable_distant_audit_devices(self):
        """
        Disable audit devices not found in conf
        """
        self.logger.debug("Disabling audit devices")
        for audit_device in self.distant_audit_devices:
            if audit_device not in self.local_audit_devices:
                self.logger.info("Disabling: " + str(audit_device))
                self.vault_client.audit_disable(audit_device.path)

    def enable_distant_audit_devices(self):
        """
        Enable audit devices found in conf
        """
        self.logger.debug("Enabling audit devices")
        for audit_device in self.local_audit_devices:
            if audit_device not in self.distant_audit_devices:
                self.logger.info("Enabling: " + str(audit_device))
                self.vault_client.audit_enable(
                    audit_device.type,
                    audit_device.path,
                    audit_device.description,
                    audit_device.options
                )

    def run(self, arg_parser, parsed_args):
        """
        Module entry point

        :param parsed_args: Arguments parsed fir this module
        :type parsed_args: argparse.ArgumentParser.parse_args()
        """
        self.parsed_args = parsed_args
        self.arg_parser = arg_parser
        self.logger.debug("Module " + self.module_name + " started")
        if self.parsed_args.push:
            self.logger.info("Pushing audit devices configuration to Vault")
            self.read_configuration()
            self.vault_client = VaultClient(self.base_logger)
            self.vault_client.authenticate()
            self.get_distant_audit_devices()
            self.get_local_audit_devices()
            for audit_device in self.local_audit_devices:
                if audit_device in self.distant_audit_devices:
                    self.logger.debug("Audit device remaining unchanged " +
                                      str(audit_device))
            self.disable_distant_audit_devices()
            self.enable_distant_audit_devices()
            self.logger.info("Audit devices successfully pushed to Vault")
