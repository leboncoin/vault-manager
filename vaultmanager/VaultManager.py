import os
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
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(logging.DEBUG)
        stream_handler.setFormatter(formatter)
        self.logger.addHandler(stream_handler)

    def initialize_arg_parser(self):
        self.logger.debug("initializing arguments parser")
        self.arg_parser = argparse.ArgumentParser(description="Vault configuration manager")
        self.arg_parser.add_argument('-v', '--verbose', action='store_true', help="enable verbose mode")
        subparsers = self.arg_parser.add_subparsers()
        self.modules = dict()
        for file in glob.glob(os.path.join(self.module_path, 'modules', 'VaultManager*.py')):
            self.logger.debug("Module " + file + " found")
            module_name = os.path.splitext(os.path.basename(file))[0]
            module_short_name = module_name.replace("vaultmanager", "").lower()
            try:
                module = getattr(importlib.import_module('modules.' + module_name), module_name)
            except ImportError:
                module = getattr(importlib.import_module('vaultmanager.modules.' + module_name), module_name)
            self.modules[module_short_name] = module(self.base_logger_name, subparsers)
        self.parsed_arguments = self.arg_parser.parse_args()
        self.modules[module_short_name].run(self.parsed_arguments)
