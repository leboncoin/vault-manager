import os
import sys
import glob
import signal
import argparse
import logging
import importlib
import getpass
import coloredlogs
import traceback
try:
    import lib.utils as utils
except ImportError:
    import vaultmanager
    import vaultmanager.lib.utils as utils


class LoggerWrapper(logging.Logger):

    _has_error = False

    def __init__(self, name):
        logging.Logger.__init__(self, name)

    def error(self, msg, *args, **kwargs):
        self._has_error = True
        super(LoggerWrapper, self).error(msg, *args, **kwargs)

    def critical(self, msg, *args, **kwargs):
        self._has_error = True
        super(LoggerWrapper, self).critical(msg, *args, **kwargs)

    def has_error(self):
        return self._has_error


class VaultManager:
    logger = None
    module_path = None
    arg_parser = None
    modules = None
    base_logger_name = None
    parsed_arguments = None
    log_format = None
    log_format_verbose_1 = None
    log_format_verbose_2 = None
    log_level_styles = None
    log_field_styles = None

    def __init__(self, module_path):
        signal.signal(signal.SIGINT, self.signal_handler)
        self.base_logger_name = "VaultManager"
        logging.setLoggerClass(LoggerWrapper)
        self.set_logger()
        self.module_path = module_path
        self.logger.debug("Module path is: " + self.module_path)
        self.initialize_arg_parser()

    def signal_handler(self, sig, frame):
        """
        Called in case of a manual

        :param sig: Signal received
        :param frame: Frame object
        """
        self.logger.warning("SIGINT received")
        self.logger.warning("There's no tasks rollback in case of "
                            "manual interruption")
        self.logger.warning("Some tasks may stay partially done and depending "
                            "on the interrupted task, some Vault data can "
                            "be corrupted")
        trace = "Interruption point:"
        for idx, f_summary in enumerate(traceback.extract_stack(frame)):
            trace += "\n  %s:%s in %s\n\t%s" % (f_summary.filename, f_summary.lineno, f_summary.name, f_summary.line)
        self.logger.warning(trace)
        self.logger.warning("Exiting. Return code: 0")
        sys.exit(0)

    def set_logger_styles(self):
        """
        Change default values for coloredlogs and logger format
        """
        self.log_format = "%(message)s"
        self.log_format_verbose_1 = "%(asctime)s %(levelname)-8s %(message)s"
        self.log_format_verbose_2 = "%(asctime)s,%(msecs)03d %(levelname)-8s %(name)s.%(funcName)s:%(lineno)d\n%(message)s"

        self.log_level_styles = dict(coloredlogs.DEFAULT_LEVEL_STYLES)
        self.log_level_styles["info"] = {"color": "white"}
        self.log_level_styles["debug"] = {"color": "green"}
        self.log_level_styles["critical"] = {"color": "magenta"}

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
        formatter = logging.Formatter(self.log_format)
        stream_handler = logging.StreamHandler(stream=sys.stdout)
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
            # When upgrading to python 2.7
            # handler.setStream(sys.stderr)
            if self.parsed_arguments.verbose == 1:
                handler.setFormatter(
                    coloredlogs.ColoredFormatter(
                        self.log_format_verbose_1,
                        level_styles=self.log_level_styles,
                        field_styles=self.log_field_styles
                    )
                )
            elif self.parsed_arguments.verbose >= 2:
                handler.setLevel(logging.DEBUG)
                handler.setFormatter(
                    coloredlogs.ColoredFormatter(
                        self.log_format_verbose_2,
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
            '-V', '--version', action='store_true',
            help="display version and exit"
        )
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
        self.arg_parser.add_argument(
            "--vault-config", nargs='?',
            default=None, const=None,
            help="Specify location of vault_config folder"
        )

    def fetch_argument_values(self):
        """
        Fetch arguments values from env vars if needed
        """
        self.logger.debug("Fetch arguments values")

        self.logger.debug("Fetch Vault address")
        self.parsed_arguments.vault_addr = utils.get_var_or_env(
            self.logger, self.parsed_arguments.vault_addr, "VAULT_ADDR"
        )

        self.logger.debug("Fetch Vault target address")
        self.parsed_arguments.vault_target_addr = utils.get_var_or_env(
            self.logger,
            self.parsed_arguments.vault_target_addr, "VAULT_TARGET_ADDR"
        )

        self.logger.debug("Fetch Vault config folder path")
        self.parsed_arguments.vault_config = utils.get_var_or_env(
            self.logger, self.parsed_arguments.vault_config, "VAULT_CONFIG"
        )

        self.logger.debug("Fetch Vault token")
        if self.parsed_arguments.vault_token:
            self.logger.debug("Asking for Vault token")
            self.parsed_arguments.vault_token = getpass.getpass("Vault token: ")
        else:
            self.parsed_arguments.vault_token = utils.get_var_or_env(
                self.logger, self.parsed_arguments.vault_token, "VAULT_TOKEN"
            )

        self.logger.debug("Fetch Vault target token")
        if self.parsed_arguments.vault_target_token:
            self.logger.debug("Asking for Vault target token")
            self.parsed_arguments.vault_target_token = getpass.getpass(
                "Vault target token: ")
        else:
            self.parsed_arguments.vault_target_token = utils.get_var_or_env(
                self.logger,
                self.parsed_arguments.vault_target_token, "VAULT_TARGET_TOKEN"
            )

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
                module = getattr(importlib.import_module('modules.' + module_name), module_name)
            except ImportError:
                module = getattr(importlib.import_module(
                    'vaultmanager.modules.' + module_name),
                    module_name
                )
            self.modules[module_short_name] = module(self.base_logger_name)
            self.modules[module_short_name].initialize_subparser(subparsers)
        self.parsed_arguments = self.arg_parser.parse_args()
        self.adjust_log_level()
        self.fetch_argument_values()
        if self.parsed_arguments.version:
            try:
                self.logger.info(
                    self.base_logger_name + " v" + vaultmanager.__version__
                )
            except NameError:
                self.logger.error("vaultmanager is not installed")
        elif len(sys.argv) <= 2:
            print()
            print(self.arg_parser.print_help())
        else:
            # Start the specified module
            if self.parsed_arguments.dry_run:
                self.logger.info("RUNNING IN DRY MODE")
            try:
                self.modules[self.parsed_arguments.module_name].run(
                    vars(self.parsed_arguments)
                )
                # if logger has logged messages > WARNING
                if logging.getLogger('VaultManager.VaultClient').has_error():
                    self.logger.error("Error found during execution" + "\n")
                    exit(1)
            except ValueError as e:
                self.logger.error(str(e) + "\n")
                self.arg_parser.print_help()
                exit(1)
