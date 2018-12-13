import os
import logging
try:
    from lib.VaultClient import VaultClient
    import lib.utils as utils
except ImportError:
    from vaultmanager.lib.VaultClient import VaultClient
    import vaultmanager.lib.utils as utils


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

    def connect_to_vault(self, vault_addr, vault_token):
        """
        Connect to a Vault instance

        :param vault_addr: Vault URL
        :type vault_addr: str
        :param vault_token: Vault token
        :type vault_token: str
        :return: VaultClient
        """
        self.logger.debug("Connecting to Vault instance '%s'" % vault_addr)
        vault_client = VaultClient(
            self.base_logger,
            dry=self.parsed_args.dry_run,
            vault_addr=vault_addr,
            skip_tls=self.parsed_args.skip_tls
        )
        vault_client.authenticate(vault_token)
        return vault_client

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

    def read_from_vault(self, path_to_read, vault_client=None):
        """
        Read secret tree from Vault

        :param path_to_read: secret path to read and return
        :type path_to_read: str
        :param vault_client: VaultClient instance
        :type vault_client: VaultClient
        :return dict(dict)
        """
        self.logger.debug("Reading kv tree")
        # TODO: to delete this if
        if not vault_client:
            vault_client = VaultClient(
                self.base_logger,
                dry=self.parsed_args.dry_run,
                skip_tls=self.parsed_args.skip_tls
            )
            vault_client.authenticate()
        kv_full = {}
        kv_list = vault_client.secrets_tree_list(
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
            secret_target_path = utils.list_to_string(
                target_path.split('/') + secret.split('/')[len(exported_path.split('/')):],
                separator="/"
            )
            self.logger.debug(
                "Exporting secret: " + secret + " to " + secret_target_path
            )
            vault_client.write(secret_target_path, exported_kv[secret],
                               hide_all=True)

    def delete_from_vault(self, kv_to_delete, vault_client=None):
        """
        Delete all secrets at and under specified path

        :param kv_to_delete: list of all secrets paths to delete
        :type kv_to_delete: list
        :param vault_client: VaultClient instance
        :type vault_client: VaultClient
        """
        self.logger.debug("Deleting secrets from " + os.environ["VAULT_ADDR"])
        # TODO: to delete this if
        if not vault_client:
            vault_client = VaultClient(
                self.base_logger,
                dry=self.parsed_args.dry_run,
                skip_tls=self.parsed_args.skip_tls
            )
            vault_client.authenticate()
        for secret in kv_to_delete:
            self.logger.info("Deleting '" + secret + "'")
            vault_client.delete(secret)

    def kv_export(self):
        """
        Method running the export function of KV module
        """
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

    def kv_copy(self):
        """
        Method running the copy function of KV module
        """
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

    def kv_delete(self):
        """
        Method running the delete function of KV module
        """
        self.logger.debug("KV Delete starting")

        missing_args = utils.keys_exists_in_dict(
            self.logger, vars(self.parsed_args),
            [{"key": "vault_addr", "exc": [None, '']},
             {"key": "vault_token", "exc": [None, False]}]
        )
        if len(missing_args):
            raise ValueError(
                "Following arguments are missing %s" %
                [k['key'].replace("_", "-") for k in missing_args]
            )
        vault_client = self.connect_to_vault(
            self.parsed_args.vault_addr,
            self.parsed_args.vault_token
        )
        self.logger.info("Deleting all secrets at and under %s at %s" %
                         (self.parsed_args.delete[0],
                          os.environ["VAULT_ADDR"]))
        exported_kv = self.read_from_vault(
            self.parsed_args.delete[0], vault_client=vault_client
        )
        if len(exported_kv):
            self.delete_from_vault(exported_kv, vault_client=vault_client)
            self.logger.debug("Secrets successfully deleted")
        else:
            self.logger.info("No secrets to delete")

    def run(self, arg_parser, parsed_args):
        """
        Module entry point

        :param arg_parser: Arguments parser instance
        :param parsed_args: Arguments parsed fir this module
        :type parsed_args: argparse.ArgumentParser.parse_args()
        """
        self.parsed_args = parsed_args
        self.arg_parser = arg_parser
        if not any([self.parsed_args.export, self.parsed_args.copy,
                    self.parsed_args.delete]):
            self.logger.error("One argument should be specified")
            self.subparser.print_help()
            return False
        self.logger.debug("Module " + self.module_name + " started")
        try:
            if self.parsed_args.export:
                self.kv_export()
            elif self.parsed_args.copy:
                self.kv_copy()
            elif self.parsed_args.delete:
                self.kv_delete()
        except ValueError as e:
            self.logger.error(str(e) + "\n")
            self.arg_parser.print_help()
