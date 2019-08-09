import os
import logging
import yaml
from collections import namedtuple
try:
    from lib.VaultClient import VaultClient
    from lib.VaultAuditDevice import VaultAuditDevice
    import lib.utils as utils
except ImportError:
    from vaultmanager.lib.VaultClient import VaultClient
    from vaultmanager.lib.VaultAuditDevice import VaultAuditDevice
    import vaultmanager.lib.utils as utils


class VaultManagerAudit:
    """
    Audit Module
    """
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

    def __init__(self, base_logger=None):
        """
        :param base_logger: main class name
        :type base_logger: string
        :param subparsers: list of all subparsers
        :type subparsers: argparse.ArgumentParser.add_subparsers()
        """
        self.base_logger = base_logger
        if base_logger:
            self.logger = logging.getLogger(base_logger + "." + self.__class__.__name__)
        else:
            self.logger = logging.getLogger()
        self.logger.debug("Initializing VaultManagerAudit")

    def initialize_subparser(self, subparsers):
        """
        Add the subparser of this specific module to the list of all subparsers

        :param subparsers: list of all subparsers
        :type subparsers: argparse.ArgumentParser.add_subparsers()
        :return:
        """
        self.logger.debug("Initializing subparser")
        self.module_name = \
            self.__class__.__name__.replace("VaultManager", "").lower()
        self.subparser = subparsers.add_parser(
            self.module_name, help=self.module_name + ' management [DEPRECATED]'
        )
        self.subparser.add_argument("--push", action='store_true',
                                    help="Push audit configuration to Vault")
        self.subparser.set_defaults(module_name=self.module_name)

    def read_configuration(self):
        """
        Read configuration file
        """
        self.logger.debug("Reading configuration")
        with open(os.path.join(self.kwargs.vault_config, "audit-devices.yml"),
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

    def check_args_integrity(self):
        """
        Checking provided arguments integrity
        """
        self.logger.debug("Checking arguments integrity")
        args_false_count = [self.kwargs.push].count(False)
        args_none_count = [self.kwargs.push].count(None)
        no_args_count = args_false_count + args_none_count
        if no_args_count in [1]:
            self.logger.critical("you must specify a command")
            return False
        return True

    def audit_push(self):
        """
        Push secrets engines configuration to Vault
        """
        self.logger.info("Pushing audit devices configuration to Vault")
        self.read_configuration()
        self.get_distant_audit_devices()
        self.get_local_audit_devices()
        for audit_device in self.local_audit_devices:
            if audit_device in self.distant_audit_devices:
                self.logger.info("Audit device remaining unchanged " +
                                 str(audit_device))
        self.disable_distant_audit_devices()
        self.enable_distant_audit_devices()
        self.logger.info("Audit devices successfully pushed to Vault")

    def run(self, kwargs):
        """
        Module entry point

        :param kwargs: Arguments parsed
        :type kwargs: dict
        """
        # Convert kwargs to an Object with kwargs dict as class vars
        self.kwargs = namedtuple("KwArgs", kwargs.keys())(*kwargs.values())
        self.logger.debug("Module " + self.module_name + " started")
        if not self.check_args_integrity():
            self.subparser.print_help()
            return False
        missing_args = utils.keys_exists_in_dict(
            self.logger, dict(self.kwargs._asdict()),
            [{"key": "vault_addr", "exc": [None, '']},
            {"key": "vault_token", "exc": [None, False]},
            {"key": "vault_config", "exc": [None, False, '']}]
        )
        if len(missing_args):
            raise ValueError(
                "Following arguments are missing %s\n" % [
                    k['key'].replace("_", "-") for k in missing_args]
            )
        self.vault_client = VaultClient(
            self.base_logger,
            vault_addr=self.kwargs.vault_addr,
            dry=self.kwargs.dry_run,
            skip_tls=self.kwargs.skip_tls
        )
        self.vault_client.authenticate()
        if self.kwargs.push:
            self.audit_push()
