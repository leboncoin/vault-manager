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

    # TODO: migrate in utils
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
        self.subparser.add_argument("--copy-path", nargs=2,
                                    help="""copy kv store from specified path
                                    COPY_FROM_PATH from $VAULT_ADDR instance
                                    to $VAULT_TARGET_ADDR at path COPY_TO_PATH.
                                    $VAULT_TOKEN is used for $VAULT_ADDR and
                                    $VAULT_TARGET_TOKEN is used for
                                    $VAULT_TARGET_ADDR""",
                                    metavar=("COPY_FROM_PATH", "COPY_TO_PATH"))
        self.subparser.add_argument("--copy-secret", nargs=2,
                                    help="""copy one secret from  $VAULT_ADDR
                                    instance at SECRET_TO_COPY to
                                    $VAULT_TARGET_ADDR at SECRET_TARGET""",
                                    metavar=("SECRET_TO_COPY", "SECRET_TARGET"))
        self.subparser.add_argument("--delete", nargs='+',
                                    help="""delete PATH_TO_DELETE and all
                                    secrets under it from $VAULT_ADDR instance.
                                    $VAULT_TOKEN is used for $VAULT_ADDR""",
                                    metavar="PATHS_TO_DELETE")
        self.subparser.add_argument("--count", nargs='+',
                                    help="""count all secrets on $VAULT_ADDR
                                    instance under SECRET_PATHS""",
                                    metavar="SECRET_PATHS")
        self.subparser.add_argument("--find-duplicates", nargs='+',
                                    help="""search and display duplicates on
                                    $VAULT_ADDR instance under SECRET_PATHS""",
                                    metavar="SECRET_PATHS")
        self.subparser.add_argument("-e", "--exclude", nargs='+',
                                    help="""paths to excludes from count or
                                    find-duplicates""",
                                    metavar="SECRET_PATHS")
        self.subparser.set_defaults(module_name=self.module_name)

    def read_from_vault(self, path_to_read, vault_client):
        """
        Read secret tree from Vault

        :param path_to_read: secret path to read and return
        :type path_to_read: str
        :param vault_client: VaultClient instance
        :type vault_client: VaultClient
        :return dict(dict)
        """
        self.logger.debug("Reading kv tree")
        kv_full = {}
        kv_list = vault_client.secrets_tree_list(
            path_to_read
        )
        self.logger.debug("Secrets found: " + str(kv_list))
        for kv in kv_list:
            kv_full[kv] = vault_client.read_secret(kv)
        return kv_full

    def push_to_vault(self, exported_path, exported_kv, target_path, vault_client):
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
        for secret in exported_kv:

            secret_target_path = utils.list_to_string(
                self.logger,
                target_path.split('/') + secret.split('/')[len(exported_path.split('/')):],
                separator="/"
            )
            self.logger.info(
                "Exporting secret: " + secret + " to " + secret_target_path
            )
            vault_client.write(secret_target_path, exported_kv[secret],
                               hide_all=True)

    def delete_from_vault(self, kv_to_delete, vault_client):
        """
        Delete all secrets at and under specified path

        :param kv_to_delete: list of all secrets paths to delete
        :type kv_to_delete: list
        :param vault_client: VaultClient instance
        :type vault_client: VaultClient
        """
        self.logger.debug("Deleting secrets from " + os.environ["VAULT_ADDR"])
        for secret in kv_to_delete:
            self.logger.info("Deleting '" + secret + "'")
            vault_client.delete(secret)

    def kv_copy_secret(self):
        """
        Method running the copy_secret function of KV module
        """
        self.logger.debug("KV copy secret starting")
        missing_args = utils.keys_exists_in_dict(
            self.logger, vars(self.parsed_args),
            [{"key": "vault_addr", "exc": [None, '']},
             {"key": "vault_token", "exc": [None, False]},
             {"key": "vault_target_addr", "exc": [None, '']},
             {"key": "vault_target_token", "exc": [None, False]}]
        )
        if len(missing_args):
            raise ValueError(
                "Following arguments are missing %s" %
                [k['key'].replace("_", "-") for k in missing_args]
            )
        self.logger.info("Copying %s from %s to %s on %s" %
                         (
                             self.parsed_args.copy_secret[0],
                             self.parsed_args.vault_addr,
                             self.parsed_args.copy_secret[1],
                             self.parsed_args.vault_target_addr
                         )
                         )
        vault_client = self.connect_to_vault(
            self.parsed_args.vault_addr,
            self.parsed_args.vault_token
        )
        secret_to_copy = vault_client.read(self.parsed_args.copy_secret[0])
        if not len(secret_to_copy):
            raise AttributeError("'%s' is not a valid secret. If you're trying "
                                 "to copy a path, use --copy-path instead" %
                                 self.parsed_args.copy_secret[0])
        vault_target_client = self.connect_to_vault(
            self.parsed_args.vault_addr,
            self.parsed_args.vault_token
        )
        vault_target_client.write(
            self.parsed_args.copy_secret[1], secret_to_copy, hide_all=True
        )
        self.logger.info("Secret '%s' successfully copied" %
                         self.parsed_args.copy_secret[0])

    def kv_copy_path(self):
        """
        Method running the copy_path function of KV module
        """
        self.logger.debug("KV copy path starting")
        missing_args = utils.keys_exists_in_dict(
            self.logger, vars(self.parsed_args),
            [{"key": "vault_addr", "exc": [None, '']},
             {"key": "vault_token", "exc": [None, False]},
             {"key": "vault_target_addr", "exc": [None, '']},
             {"key": "vault_target_token", "exc": [None, False]}]
        )
        if len(missing_args):
            raise ValueError(
                "Following arguments are missing %s" %
                [k['key'].replace("_", "-") for k in missing_args]
            )
        self.logger.info("Copying %s from %s to %s on %s" %
                         (
                             self.parsed_args.copy_path[0],
                             self.parsed_args.vault_addr,
                             self.parsed_args.copy_path[1],
                             self.parsed_args.vault_target_addr
                         )
                         )
        vault_client = self.connect_to_vault(
            self.parsed_args.vault_addr,
            self.parsed_args.vault_token
        )
        exported_kv = self.read_from_vault(
            self.parsed_args.copy_path[0], vault_client
        )
        if not len(exported_kv):
            raise AttributeError("No path to copy")
        if len(exported_kv) == 1 and list(exported_kv.keys())[0] == self.parsed_args.copy_path[0]:
            raise AttributeError(
                "--copy-path should not be used to copy individual secrets."
                " Use --copy-secret instead"
            )

        vault_target_client = self.connect_to_vault(
            self.parsed_args.vault_addr,
            self.parsed_args.vault_token
        )
        self.push_to_vault(self.parsed_args.copy_path[0], exported_kv,
                           self.parsed_args.copy_path[1],
                           vault_target_client)
        self.logger.info("Path successfully copied")

    def kv_delete(self):
        """
        Method running the delete function of KV module
        """
        self.logger.debug("KV delete starting")

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
        for to_delete in self.parsed_args.delete:
            self.logger.info("Deleting all secrets at and under %s at %s" %
                             (to_delete,
                              os.environ["VAULT_ADDR"]))
            exported_kv = self.read_from_vault(to_delete, vault_client)
            if len(exported_kv):
                self.delete_from_vault(exported_kv, vault_client)
                self.logger.debug("Secrets at '%s' successfully deleted" %
                                  to_delete)
            else:
                self.logger.error("No secrets to delete at '%s'" % to_delete)

    def kv_count(self):
        """
        Method running the count function of KV module
        """
        self.logger.debug("KV count starting")
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
        total_secrets = 0
        total_kv = 0
        excluded = self.parsed_args.exclude or []
        for path in self.parsed_args.count:
            self.logger.info("At path '" + path + "'")
            all_secrets = vault_client.secrets_tree_list(path, excluded)
            self.logger.info("\tSecrets count: " + str(len(all_secrets)))
            total_secrets += len(all_secrets)
            kv_count = 0
            for secret_path in all_secrets:
                kv_count += len(vault_client.read(secret_path))
            total_kv += kv_count
            self.logger.info("\tK/V count: " + str(kv_count))
        self.logger.info("Total")
        self.logger.info("\tSecrets count: " + str(total_secrets))
        self.logger.info("\tK/V count: " + str(total_kv))

    def kv_find_duplicates(self):
        """
        Method running the count function of KV module
        """
        self.logger.debug("KV find duplicates starting")

    def run(self, arg_parser, parsed_args):
        """
        Module entry point

        :param arg_parser: Arguments parser instance
        :param parsed_args: Arguments parsed fir this module
        :type parsed_args: argparse.ArgumentParser.parse_args()
        """
        self.parsed_args = parsed_args
        self.arg_parser = arg_parser
        if not any([self.parsed_args.copy_path, self.parsed_args.count,
                    self.parsed_args.copy_secret, self.parsed_args.delete,
                    self.parsed_args.find_duplicates]):
            self.logger.error("One argument should be specified")
            self.subparser.print_help()
            return False
        self.logger.debug("Module " + self.module_name + " started")
        try:
            if self.parsed_args.copy_path:
                self.kv_copy_path()
            elif self.parsed_args.copy_secret:
                self.kv_copy_secret()
            elif self.parsed_args.delete:
                self.kv_delete()
            elif self.parsed_args.count:
                self.kv_count()
            elif self.parsed_args.find_duplicates:
                self.kv_find_duplicates()
        except ValueError as e:
            self.logger.error(str(e) + "\n")
            self.arg_parser.print_help()
        except AttributeError as e:
            self.logger.error(str(e))
