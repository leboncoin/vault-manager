import os
import logging
try:
    from lib.VaultClient import VaultClient
except ImportError:
    from vaultmanager.lib.VaultClient import VaultClient


class VaultManagerKV:
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
        self.logger.debug("Initializing VaultManagerKV")
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
        self.subparser.add_argument("--export", nargs=1,
                                    help="""export kv store from specified path
                                    PATH_TO_EXPORT from $VAULT_ADDR instance
                                    to $VAULT_TARGET_ADDR at the same path.
                                    $VAULT_TOKEN is used for $VAULT_ADDR and
                                    $VAULT_TARGET_TOKEN is used for
                                    $VAULT_TARGET_ADDR""",
                                    metavar="PATH_TO_EXPORT")
        self.subparser.add_argument("--copy", nargs=2,
                                    help="""copy kv store from specified path
                                    COPY_FROM_PATH from $VAULT_ADDR instance
                                    to $VAULT_TARGET_ADDR at path COPY_TO_PATH.
                                    $VAULT_TOKEN is used for $VAULT_ADDR and
                                    $VAULT_TARGET_TOKEN is used for
                                    $VAULT_TARGET_ADDR""",
                                    metavar=("COPY_FROM_PATH", "COPY_TO_PATH"))
        self.subparser.add_argument("--delete", nargs=1,
                                    help="""delete PATH_TO_DELETE and all
                                    secrets under it from $VAULT_ADDR instance.
                                    $VAULT_TOKEN is used for $VAULT_ADDR""",
                                    metavar="PATH_TO_DELETE")
        self.subparser.set_defaults(module_name=self.module_name)

    def check_env_vars(self):
        """
        Check if all needed env vars are set

        :return: bool
        """
        self.logger.debug("Checking env variables")
        needed_env_vars_1 = ["VAULT_ADDR", "VAULT_TOKEN"]
        needed_env_vars_2 = needed_env_vars_1 + ["VAULT_TARGET_ADDR",
                                                 "VAULT_TARGET_TOKEN"]
        if self.parsed_args.delete:
            if not all(env_var in os.environ for env_var in needed_env_vars_1):
                self.logger.critical("The following env vars must be set")
                self.logger.critical(str(needed_env_vars_1))
                return False
        else:
            if not all(env_var in os.environ for env_var in needed_env_vars_2):
                self.logger.critical("The following env vars must be set")
                self.logger.critical(str(needed_env_vars_2))
                return False
        self.logger.debug("All env vars are set")
        self.logger.info("Vault address: " + os.environ["VAULT_ADDR"])
        return True

    def read_from_vault(self, path_to_read):
        """
        Read secret tree from Vault

        :param path_to_read: secret path to read and return
        :type path_to_read: str
        :return dict(dict)
        """
        self.logger.debug("Reading kv tree")
        vault_client = VaultClient(
            self.base_logger,
            dry=self.parsed_args.dry_run,
            skip_tls=self.parsed_args.skip_tls
        )
        vault_client.authenticate()
        kv_full = {}
        kv_list = vault_client.get_secrets_tree(
            path_to_read
        )
        self.logger.debug("Secrets found: " + str(kv_list))
        for kv in kv_list:
            kv_full[kv] = vault_client.read_secret(kv)
        return kv_full

    def push_to_vault(self, exported_path, exported_kv, target_path):
        """
        Push exported kv to Vault

        :param exported_path: export root path
        :type exported_path: str
        :param target_path: push kv to this path
        :type target_path: str
        :param exported_kv: Exported KV store
        :type exported_kv: dict
        """
        self.logger.debug("Pushing exported kv to Vault")
        vault_client = VaultClient(
            self.base_logger,
            dry=self.parsed_args.dry_run,
            vault_addr=os.environ["VAULT_TARGET_ADDR"],
            skip_tls=self.parsed_args.skip_tls
        )
        vault_client.authenticate(os.environ["VAULT_TARGET_TOKEN"])
        for secret in exported_kv:
            secret_target_path = self.__list_to_string(
                target_path.split('/') + secret.split('/')[len(exported_path.split('/')):]
                , separator="/"
            )
            self.logger.debug(
                "Exporting secret: " + secret + " to " + secret_target_path
            )
            vault_client.write(secret_target_path, exported_kv[secret],
                               hide_all=True)

    def delete_from_vault(self, kv_to_delete):
        """
        Delete all secrets at and under specified path

        :param kv_to_delete: list of all secrets paths to delete
        :type kv_to_delete: list
        """
        self.logger.debug("Deleting secrets from " + os.environ["VAULT_ADDR"])
        vault_client = VaultClient(
            self.base_logger,
            dry=self.parsed_args.dry_run,
            skip_tls=self.parsed_args.skip_tls
        )
        vault_client.authenticate()
        for secret in kv_to_delete:
            self.logger.debug("Deleting " + secret)
            vault_client.delete(secret)

    def run(self, arg_parser, parsed_args):
        """
        Module entry point

        :param arg_parser: Arguments parser instance
        :param parsed_args: Arguments parsed fir this module
        :type parsed_args: argparse.ArgumentParser.parse_args()
        """
        self.parsed_args = parsed_args
        self.arg_parser = arg_parser
        if not self.check_env_vars():
            return False
        if not self.parsed_args.export and not self.parsed_args.copy \
                and not self.parsed_args.delete:
            self.logger.error("One argument should be specified")
            self.subparser.print_help()
            return False
        self.logger.debug("Module " + self.module_name + " started")
        if self.parsed_args.export:
            self.logger.info("Exporting %s from %s to %s" %
                             (
                                 self.parsed_args.export[0],
                                 os.environ["VAULT_ADDR"],
                                 os.environ["VAULT_TARGET_ADDR"]
                             )
                             )
            exported_kv = self.read_from_vault(self.parsed_args.export[0])
            if len(exported_kv):
                self.push_to_vault(self.parsed_args.export[0], exported_kv,
                                   self.parsed_args.export[0])
                self.logger.info("Secrets successfully exported")
            else:
                self.logger.info("No secrets to export")
        elif self.parsed_args.copy:
            self.logger.info("Copying %s from %s to %s on %s" %
                             (
                                 self.parsed_args.copy[0],
                                 os.environ["VAULT_ADDR"],
                                 self.parsed_args.copy[1],
                                 os.environ["VAULT_TARGET_ADDR"]
                             )
                             )
            exported_kv = self.read_from_vault(self.parsed_args.copy[0])
            if len(exported_kv):
                self.push_to_vault(self.parsed_args.copy[0], exported_kv,
                                   self.parsed_args.copy[1])
                self.logger.info("Secrets successfully copied")
            else:
                self.logger.info("No secrets to copy")
        elif self.parsed_args.delete:
            self.logger.info("Deleting all secrets at and under %s at %s" %
                             (self.parsed_args.delete[0],
                              os.environ["VAULT_ADDR"]))
            exported_kv = self.read_from_vault(self.parsed_args.delete[0])
            if len(exported_kv):
                self.delete_from_vault(exported_kv)
                self.logger.debug("Secrets successfully deleted")
            else:
                self.logger.info("No secrets to delete")


    def __list_to_string(self, lst, delimiter="", separator=","):
        """
        Convert a list to string

        :param lst: list to serialize
        :type lst: list
        :param delimiter: quoting string
        :type delimiter: str
        :param separator: separator between list elements
        :type separator: str

        :return: str
        """
        self.logger.debug("Converting list " + str(lst))
        lst = [elem for elem in lst if lst]
        target = ""
        for idx, elem in enumerate(lst):
            if idx != 0:
                target += separator
            target += delimiter + elem + delimiter
        self.logger.debug("Returning: " + target)
        return target



