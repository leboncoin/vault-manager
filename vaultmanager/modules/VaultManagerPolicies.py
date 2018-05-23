import logging


class VaultManagerPolicies:
    logger = None
    subparser = None
    parsed_args = None
    module_name = None

    def __init__(self, base_logger, subparsers):
        self.logger = logging.getLogger(base_logger + "." + self.__class__.__name__)
        self.logger.debug("Initializing VaultManagerPolicies")
        self.initialize_subparser(subparsers)

    def initialize_subparser(self, subparsers):
        self.logger.debug("Initializing subparser")
        self.module_name = self.__class__.__name__.replace("VaultManager", "").lower()
        self.subparser = subparsers.add_parser(self.module_name, help=self.module_name + ' management')
        self.subparser.add_argument("-a", "--argument", action="store_true")
        self.subparser.set_defaults(module_name=self.module_name)

    def get_subparser(self):
        return self.subparser

    def run(self, parsed_args):
        self.parsed_args = parsed_args
        self.logger.debug("Module " + self.module_name + " started")
        print(self.parsed_args)
