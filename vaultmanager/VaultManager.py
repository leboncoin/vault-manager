import os
import sys
import glob
import argparse
import logging
import importlib
import getpass
import coloredlogs


class VaultManager:
    logger = None
    module_path = None
    arg_parser = None
    modules = None
    base_logger_name = None
    parsed_arguments = None
    log_format = None
    log_format_verbose = None
    log_level_styles = None
    log_field_styles = None

    def __init__(self, module_path):
        self.base_logger_name = "VaultManager"
        self.set_logger()
        self.module_path = module_path
        self.logger.debug("Module path is: " + self.module_path)
        self.initialize_arg_parser()

    def set_logger_styles(self):
        """
        Change default values for coloredlogs and logger format
        """
        self.log_format ="%(asctime)s %(levelname)-8s %(message)s"
        self.log_format_verbose = "%(asctime)s,%(msecs)03d %(levelname)-8s %(name)s.%(funcName)s:%(lineno)d\n%(message)s"

        self.log_level_styles = dict(coloredlogs.DEFAULT_LEVEL_STYLES)
        self.log_level_styles["info"] = {"color": "white"}
        self.log_level_styles["debug"] = {"color": "green"}
        self.log_level_styles["critical"] = {
            "color": "magenta",
            "bold": coloredlogs.CAN_USE_BOLD_FONT
        }
        self.log_field_styles = dict(coloredlogs.DEFAULT_FIELD_STYLES)
        self.log_field_styles["asctime"] = {"color": "yellow", "bright": True}
        self.log_field_styles["name"] = {"color": "blue"}
        self.log_field_styles["lineno"] = {"color": "yellow"}
        self.log_field_styles["funcname"] = {"color": "cyan"}
        self.log_field_styles["levelname"] = {"color": "white"}

    def set_logger(self):
        """
        Initialize logger
        """
        logging.getLogger().setLevel(logging.INFO)

        self.logger = logging.getLogger(self.base_logger_name)
        self.logger.setLevel(logging.INFO)

        self.set_logger_styles()
        formatter = coloredlogs.ColoredFormatter(
            self.log_format,
            level_styles=self.log_level_styles,
            field_styles=self.log_field_styles
        )
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(logging.INFO)
        stream_handler.setFormatter(formatter)
        self.logger.addHandler(stream_handler)

        self.logger = logging.getLogger(self.base_logger_name + ".VaultManager")

    def adjust_log_level(self):
        """
        Change the log level of all handlers if needed
        """
        self.logger.debug("Adjust log level if needed")
        if not self.parsed_arguments.verbose:
            self.logger.debug("Log level remains unchanged")
            return
        self.logger.debug("Changing log level to " + str(logging.DEBUG))
        logging.getLogger(self.base_logger_name).setLevel(logging.DEBUG)
        for handler in logging.getLogger(self.base_logger_name).handlers:
            handler.setLevel(logging.DEBUG)
            if self.parsed_arguments.verbose >= 2:
                handler.setFormatter(
                    coloredlogs.ColoredFormatter(
                        self.log_format_verbose,
                        level_styles=self.log_level_styles,
                        field_styles=self.log_field_styles
                    )
                )
        self.logger.debug("Log level changed to " + str(logging.DEBUG))

    def add_arguments(self):
        """
        Add optional arguments to parser
        """
        self.logger.debug("Adding arguments")
        self.arg_parser.add_argument(
            '-v', '--verbose', action='count', help="enable verbose mode"
        )
        self.arg_parser.add_argument(
            '-d', '--dry-run', action='store_true',
            help="run in dry mode: No API calls"
        )
        self.arg_parser.add_argument(
            '-s', '--skip-tls', action='store_true',
            help='disable TLS verification'
        )
        self.arg_parser.add_argument(
            '--vault-addr', action='store', nargs='?',
            default=None, const=None,
            help='Vault address (https://<URL>:<PORT>)'
        )
        self.arg_parser.add_argument(
            '--vault-target-addr', action='store', nargs='?',
            default=None, const=None,
            help='Vault target address (https://<URL>:<PORT>)'
        )
        self.arg_parser.add_argument(
            '--vault-token', action='store_true',
            help='Prompt for Vault token'
        )
        self.arg_parser.add_argument(
            '--vault-target-token', action='store_true',
            help='Prompt for Vault target token'
        )

    def fetch_argument_values(self):
        """
        Fetch arguments values from env vars if needed

        return: bool
        """
        self.logger.debug("Fetch arguments values")
        # Optional args
        self.logger.debug("Fetch Vault target address")
        if not self.parsed_arguments.vault_target_addr:
            if os.getenv('VAULT_TARGET_ADDR'):
                self.parsed_arguments.vault_target_address = os.getenv(
                    'VAULT_TARGET_ADDR')
        self.logger.debug("Fetch Vault target token")
        if not self.parsed_arguments.vault_target_token:
            if os.getenv('VAULT_TARGET_TOKEN'):
                self.parsed_arguments.vault_target_token = os.getenv(
                    'VAULT_TARGET_TOKEN')
        elif self.parsed_arguments.vault_target_token and not \
                self.parsed_arguments.vault_target_addr:
            self.logger.warning(
                "Cannot set Vault target token without Vault target address")
            return False

        # Mandatory args
        self.logger.debug("Fetch Vault address")
        if not self.parsed_arguments.vault_addr:
            if os.getenv('VAULT_ADDR'):
                self.parsed_arguments.vault_address = os.getenv('VAULT_ADDR')
            else:
                self.logger.error("Value for Vault address must be set")
                return False
        self.logger.debug("Fetch Vault token")
        if not self.parsed_arguments.vault_token:
            if os.getenv('VAULT_TOKEN'):
                self.parsed_arguments.vault_token = os.getenv('VAULT_TOKEN')
            else:
                self.logger.error("Value for Vault token must be set")
                return False
        else:
            self.logger.debug("Asking for Vault token")
            self.parsed_arguments.vault_token = getpass.getpass("Vault token: ")

        # Fetch of target token if needed. Here to respect a logical order
        if self.parsed_arguments.vault_target_token:
            self.logger.debug("Asking for Vault target token")
            self.parsed_arguments.vault_target_token = getpass.getpass(
                "Vault target token: ")
        self.logger.debug(self.parsed_arguments)
        return True

    def initialize_arg_parser(self):
        """
        Initialize parser and subparsers then launch the specified module
        """
        self.logger.debug("initializing arguments parser")
        self.arg_parser = argparse.ArgumentParser(
            description="Vault configuration manager"
        )
        self.add_arguments()
        subparsers = self.arg_parser.add_subparsers()
        # Fetch the list of all available submodules
        self.modules = dict()
        for file in glob.glob(
                os.path.join(self.module_path, 'modules', 'VaultManager*.py')):
            self.logger.debug("Module " + file + " found")
            module_name = os.path.splitext(os.path.basename(file))[0]
            module_short_name = module_name.replace("VaultManager", "").lower()
            try:
                module = getattr(
                    importlib.import_module('modules.' + module_name),
                    module_name
                )
            except ImportError:
                module = getattr(importlib.import_module(
                    'vaultmanager.modules.' + module_name),
                    module_name
                )
            self.modules[module_short_name] = module(self.base_logger_name,
                                                     subparsers)
        self.parsed_arguments = self.arg_parser.parse_args()
        self.adjust_log_level()
        self.logger.debug("Parsed arguments: " + str(self.parsed_arguments))
        if len(sys.argv) <= 2 or not self.fetch_argument_values():
            print()
            print(self.arg_parser.print_help())
        else:
            # Start the specified module
            if self.parsed_arguments.dry_run:
                self.logger.info("RUNNING IN DRY MODE")
            self.modules[self.parsed_arguments.module_name].run(
                self.arg_parser, self.parsed_arguments
            )
