import os
import sys
import glob
import argparse
import logging
import importlib


class VaultManager:
    logger = None
    module_path = None
    arg_parser = None
    modules = None
    base_logger_name = None
    parsed_arguments = None

    def __init__(self, module_path):
        self.base_logger_name = "VaultManager"
        self.set_logger()
        self.module_path = module_path
        self.logger.debug("Module path is: " + self.module_path)
        self.initialize_arg_parser()

    def set_logger(self):
        """
        Initialize logger

        :return: logger instance
        """
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)
        #formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(logging.INFO)
        stream_handler.setFormatter(formatter)
        self.logger.addHandler(stream_handler)

    def change_log_level(self, log_level=None):
        """
        Change the log level of all handlers

        :param log_level: log level
        :type log_level: logging.(CRITICAL|ERROR|WARNING|INFO|DEBUG)
        """
        self.logger.debug("Changing log level to " + str(log_level))
        if self.parsed_arguments.verbose >= 1:
            log_level = logging.DEBUG
        self.logger.setLevel(log_level)
        for handler in self.logger.handlers:
            handler.setLevel(log_level)
        self.logger.debug("Log level changed to " + str(log_level))

    def initialize_arg_parser(self):
        """
        Initialize parser and subparsers then launch the specified module
        """
        self.logger.debug("initializing arguments parser")
        self.arg_parser = argparse.ArgumentParser(
            description="Vault configuration manager"
        )
        self.arg_parser.add_argument('-v', '--verbose', action='count',
                                     help="enable verbose mode")
        self.arg_parser.add_argument('-d', '--dry-run', action='store_true',
                                     help="run in dry mode: No API calls")
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
                module = getattr(importlib.import_module('vaultmanager.modules.' + module_name), module_name)
            self.modules[module_short_name] = module(self.base_logger_name, subparsers)
        self.parsed_arguments = self.arg_parser.parse_args()
        if self.parsed_arguments.verbose:
            self.change_log_level(self.parsed_arguments.verbose)
        self.logger.debug("Parsed arguments: " + str(self.parsed_arguments))
        if len(sys.argv) <= 2:
            print(self.arg_parser.print_help())
        else:
            # Start the specified module
            if self.parsed_arguments.dry_run:
                self.logger.info("RUNNING IN DRY MODE")
            self.modules[self.parsed_arguments.module_name].run(self.arg_parser, self.parsed_arguments)
