import os
import logging
try:
    import lib.utils as utils
    from lib.VaultClient import VaultClient
except ImportError:
    from vaultmanager.lib.VaultClient import VaultClient
    import vaultmanager.lib.utils as utils


class VaultManagerModule:
    logger = None
    base_logger = None
    subparser = None
    parsed_args = None
    arg_parser = None
    module_name = None

    def __init__(self, base_logger, subparsers):
        """
        :param base_logger: main class name
        :type base_logger: string
        :param subparsers: list of all subparsers
        :type subparsers: argparse.ArgumentParser.add_subparsers()
        """
        self.base_logger = base_logger
        self.logger = logging.getLogger(base_logger + "." + self.__class__.__name__)
        self.logger.debug("Initializing VaultManagerMODULE")
        self.initialize_subparser(subparsers)

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
            self.module_name, help=self.module_name + ' management'
        )
        self.subparser.add_argument("--push", action='store_true',
                                    help="Push to Vault")
        self.subparser.set_defaults(module_name=self.module_name)

    def run(self, arg_parser, parsed_args):
        """
        Module entry point

        :param arg_parser: Arguments parser instance
        :param parsed_args: Arguments parsed fir this module
        :type parsed_args: argparse.ArgumentParser.parse_args()
        """
        self.parsed_args = parsed_args
        self.arg_parser = arg_parser
        missing_args = utils.keys_exists_in_dict(
            self.logger, vars(self.parsed_args),
            [{"key": "vault_addr", "exc": [None, '']},
             {"key": "vault_token", "exc": [None, False]}]
        )
        if len(missing_args):
            self.logger.error("Following arguments are missing %s\n" %
                              [k['key'].replace("_", "-") for k in
                               missing_args])
            self.arg_parser.print_help()
            return False
        self.logger.debug("Module " + self.module_name + " started")
        print(self.parsed_args)
