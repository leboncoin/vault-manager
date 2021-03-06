import os
import logging
import json
import random
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
    kwargs = None
    module_name = None
    dry_run = False
    skip_tls = False

    def __init__(self, base_logger=None, dry_run=False, skip_tls=False):
        """
        :param base_logger: main class name
        :type base_logger: string
        :param subparsers: list of all subparsers
        :type subparsers: argparse.ArgumentParser.add_subparsers()
        """
        self.base_logger = base_logger
        if base_logger:
            self.logger = logging.getLogger(
                base_logger + "." + self.__class__.__name__
            )
        else:
            self.logger = logging.getLogger()
        self.dry_run = dry_run
        self.skip_tls = skip_tls
        self.logger.debug("Initializing VaultManagerKV")

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
            dry=self.dry_run,
            vault_addr=vault_addr,
            skip_tls=self.skip_tls
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
                                    COPY_FROM_PATH from vault-addr instance
                                    to vault-target-addr at path COPY_TO_PATH.
                                    vault-token is used for vault-addr and
                                    vault-target-token is used for
                                    vault-target-addr""",
                                    metavar=("COPY_FROM_PATH", "COPY_TO_PATH"))
        self.subparser.add_argument("--copy-secret", nargs=2,
                                    help="""copy one secret from vault-addr
                                    instance at SECRET_TO_COPY to
                                    vault-target-addr at SECRET_TARGET""",
                                    metavar=("SECRET_TO_COPY", "SECRET_TARGET"))
        self.subparser.add_argument("--delete", nargs='+',
                                    help="""delete PATH_TO_DELETE and all
                                    secrets under it from vault-addr instance.
                                    vault-token is used for vault-addr""",
                                    metavar="PATHS_TO_DELETE")
        self.subparser.add_argument("--count", nargs='+',
                                    help="""count all secrets on vault-addr
                                    instance under SECRET_PATHS""",
                                    metavar="SECRET_PATHS")
        self.subparser.add_argument("--find-duplicates", nargs='+',
                                    help="""search and display duplicates on
                                    vault-addr instance under SECRET_PATHS""",
                                    metavar="SECRET_PATHS")
        self.subparser.add_argument("--secrets-tree", nargs='+',
                                    help="""display all secrets tree
                                    (path/to/secret) on vault-addr instance
                                     under SECRET_PATHS""",
                                    metavar="SECRET_PATHS")
        self.subparser.add_argument("--search", nargs='+',
                                    help="""try to find all SEARCH_VALUES
                                    on vault-addr instance whether it's a
                                    path or a secret""",
                                    metavar="SEARCH_VALUES")
        self.subparser.add_argument("-e", "--exclude", nargs='+',
                                    help="""paths to excludes from count,
                                    find-duplicates, secrets-tree or search""",
                                    metavar="SECRET_PATHS")
        self.subparser.add_argument("-i", "--include", nargs='+',
                                    help="""paths to include in search""",
                                    metavar="SECRET_PATHS")
        self.subparser.add_argument("--generate-tree", nargs='+',
                                    help="""paths under which will be
                                    generated a random secrets tree""",
                                    metavar="SECRET_PATHS")
        self.subparser.add_argument("--depth", nargs='?',
                                    help="""depth of tree generated by
                                    generate-tree""",
                                    metavar="DEPTH", type=int)
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

    def push_to_vault(self, exported_path, exported_kv, target_path,
                      vault_client):
        """
        Push exported kv to Vault

        :param exported_path: export root path
        :type exported_path: str
        :param target_path: push kv to this path
        :type target_path: str
        :param exported_kv: Exported KV store
        :type exported_kv: dict
        :param vault_client: VaultClient instance
        :type vault_client: VaultClient
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

    def kv_copy_secret(self, vault_addr, vault_token, vault_target_addr,
                       vault_target_token, copy_from, copy_to):
        """
        Method running the copy_secret function of KV module

        :param vault_addr: Vault source instance URL
        :type vault_addr: str
        :param vault_token: Vault source token
        :type vault_token: str
        :param vault_target_addr: Vault target instance URL
        :type vault_target_addr: str
        :param vault_target_token: Vault target token
        :type vault_target_token: str
        :param copy_from: Source secret
        :type copy_from: str
        :param copy_to: Target secret
        :type copy_to: str

        :return: bool
        """
        self.logger.debug("KV copy secret starting")
        self.logger.info("Copying %s from %s to %s on %s" %
                         (copy_from, vault_addr, copy_to, vault_target_addr))
        vault_source_client = self.connect_to_vault(vault_addr, vault_token)
        secret_to_copy = vault_source_client.read(copy_from)
        if not len(secret_to_copy):
            raise AttributeError("'%s' is not a valid secret. If you're trying "
                                 "to copy a path, use --copy-path instead" %
                                 copy_from)
        vault_target_client = self.connect_to_vault(
            vault_target_addr,
            vault_target_token
        )
        try:
            vault_target_client.write(copy_to, secret_to_copy, hide_all=True)
        except ValueError as e:
            self.logger.error("Failed to copy secret '%s' to '%s'" %
                              (copy_from, copy_to))
            self.logger.error(e)
            return False
        self.logger.info("Secret '%s' successfully copied to '%s'" %
                         (copy_from, copy_to))
        return True

    def kv_copy_path(self, vault_addr, vault_token, vault_target_addr,
                     vault_target_token, copy_from, copy_to):
        """
        Method running the copy_path function of KV module

        :param vault_addr: Vault source instance URL
        :type vault_addr: str
        :param vault_token: Vault source token
        :type vault_token: str
        :param vault_target_addr: Vault target instance URL
        :type vault_target_addr: str
        :param vault_target_token: Vault target token
        :type vault_target_token: str
        :param copy_from: Source path
        :type copy_from: str
        :param copy_to: Target path
        :type copy_to: str

        :return: bool
        """
        self.logger.debug("KV copy path starting")
        self.logger.info("Copying %s from %s to %s on %s" %
                         (copy_from, vault_addr, copy_to, vault_target_addr))
        vault_source_client = self.connect_to_vault(vault_addr, vault_token)
        exported_kv = self.read_from_vault(copy_from, vault_source_client)
        if not len(exported_kv):
            raise AttributeError("No path to copy")
        if len(exported_kv) == 1 and list(exported_kv.keys())[0] == copy_from:
            raise AttributeError(
                "--copy-path should not be used to copy individual secrets."
                " Use --copy-secret instead"
            )
        vault_target_client = self.connect_to_vault(
            vault_target_addr, vault_target_token
        )
        try:
            self.push_to_vault(
                copy_from, exported_kv, copy_to, vault_target_client
            )
        except ValueError as e:
            self.logger.error("Failed to copy path '%s' to '%s'" %
                              (copy_from, copy_to))
            self.logger.error(e)
            return False
        self.logger.info("Path successfully copied")
        return True

    def kv_delete(self, vault_addr, vault_token, paths):
        """
        Method running the delete function of KV module

        :param vault_addr: Vault instance URL
        :type vault_addr: str
        :param vault_token: Vault token
        :type vault_token: str
        :param paths: Paths to count
        :type paths: list(str)

        :return: dict of deleted secrets
        """
        self.logger.debug("KV delete starting")
        vault_client = self.connect_to_vault(
            vault_addr,
            vault_token
        )
        for to_delete in paths:
            self.logger.info("Deleting all secrets at and under %s at %s" %
                             (to_delete,
                              os.environ["VAULT_ADDR"]))
            secrets_to_delete = vault_client.secrets_tree_list(to_delete)
            if len(secrets_to_delete):
                for secret in secrets_to_delete:
                    self.logger.info("Deleting '" + secret + "'")
                    vault_client.delete(secret)
                self.logger.debug("%s secrets at '%s' successfully deleted" %
                                  (len(secrets_to_delete), to_delete))
            else:
                self.logger.error("No secrets to delete at '%s'" % to_delete)
        return secrets_to_delete

    def kv_count(self, vault_addr, vault_token, paths, excluded=[]):
        """
        Method running the count function of KV module

        :param vault_addr: Vault instance URL
        :type vault_addr: str
        :param vault_token: Vault token
        :type vault_token: str
        :param paths: Paths to count
        :type paths: list(str)
        :param excluded: Paths to exclude from count
        :type excluded: list(str)

        :return: dict
        """
        self.logger.debug("KV count starting")
        vault_client = self.connect_to_vault(
            vault_addr,
            vault_token
        )
        total_secrets = 0
        total_kv = 0
        count_dict = {}
        for path in paths:
            self.logger.debug("At path '" + path + "'")
            count_dict[path] = {"secrets_count": -1, "values_count": -1}
            all_secrets = vault_client.secrets_tree_list(path, excluded)
            self.logger.debug("\tSecrets count: " + str(len(all_secrets)))
            count_dict[path]["secrets_count"] = len(all_secrets)
            total_secrets += len(all_secrets)
            kv_count = 0
            for secret_path in all_secrets:
                kv_count += len(vault_client.read(secret_path))
            total_kv += kv_count
            self.logger.debug("\tValues count: " + str(kv_count))
            count_dict[path]["values_count"] = kv_count
        self.logger.debug("Total")
        self.logger.debug("\tSecrets count: " + str(total_secrets))
        self.logger.debug("\tValues count: " + str(total_kv))
        self.logger.info(json.dumps(count_dict, indent=4))
        return count_dict

    def kv_find_duplicates(self, vault_addr, vault_token, paths, excluded=[]):
        """
        Method running the count function of KV module

        :param vault_addr: Vault instance URL
        :type vault_addr: str
        :param vault_token: Vault token
        :type vault_token: str
        :param paths: Paths to look for duplicates
        :type paths: list(str)
        :param excluded: Paths to exclude from count
        :type excluded: list(str)

        :return: dict
        """
        self.logger.debug("KV find duplicates starting")
        vault_client = self.connect_to_vault(
            vault_addr,
            vault_token
        )
        kv_full = {}
        kv_list = []
        for path in paths:
            kv_list += vault_client.secrets_tree_list(path, excluded)
        for kv in kv_list:
            kv_full[kv] = vault_client.read_secret(kv)
        values_count = {}
        for path in kv_full:
            for key in kv_full[path]:
                if kv_full[path][key] not in values_count:
                    values_count[kv_full[path][key]] = [path + ":" + key]
                else:
                    values_count[kv_full[path][key]].append(path + ":" + key)

        grouped_duplicates = {}
        dup_counter = 0
        for elem in values_count:
            if len(values_count[elem]) > 1:
                grouped_duplicates[dup_counter] = values_count[elem]
                dup_counter += 1
        self.logger.info(json.dumps(grouped_duplicates, indent=4))
        return grouped_duplicates

    def kv_search(
            self, vault_addr, vault_token, to_search, included=[], excluded=[]
    ):
        """
        Method running the search function of KV module

        :param vault_addr: Vault instance URL
        :type vault_addr: str
        :param vault_token: Vault token
        :type vault_token: str
        :param to_search: Values to search in KV
        :type to_search: list(str)
        :param included: Paths to include in search
        :type included: list(str)
        :param excluded: Paths to exclude from search
        :type excluded: list(str)

        :return: list
        """
        self.logger.debug("KV search secrets starting")
        vault_client = self.connect_to_vault(
            vault_addr,
            vault_token
        )
        kv_full = {}
        kv_list = []
        found_values = []
        for path in included:
            kv_list += vault_client.secrets_tree_list(path, excluded)
        for kv in kv_list:
            kv_full[kv] = vault_client.read_secret(kv)

        for path in kv_full:
            for key in kv_full[path]:
                for v in to_search:
                    if v in os.path.join(path, key) or v in kv_full[path][key]:
                        found_values.append(os.path.join(path, key))

        self.logger.info(json.dumps(found_values, indent=4))
        return found_values

    def kv_secrets_tree(self, vault_addr, vault_token, paths, excluded=[]):
        """
        Method running the secrets tree function of KV module

        :param vault_addr: Vault instance URL
        :type vault_addr: str
        :param vault_token: Vault token
        :type vault_token: str
        :param paths: Paths to look for duplicates
        :type paths: list(str)
        :param excluded: Paths to exclude from count
        :type excluded: list(str)

        :return: dict
        """
        self.logger.debug("KV secrets paths starting")
        vault_client = self.connect_to_vault(
            vault_addr,
            vault_token
        )
        kv_full = {}
        for path in paths:
            kv_full[path] = vault_client.secrets_tree_list(path, excluded)
        self.logger.info(json.dumps(kv_full, indent=4))
        return kv_full

    def kv_generate_tree_recursive(self, vault_client, path, depth, count,
                                   words):
        """
        Recursive function associated with kv_generate_tree

        :param vault_client: VaultClient instance
        :type vault_client: VaultClient
        :param path: Path under which the tree will be created
        :type path: str
        :param depth: Secrets depth left
        :type depth: int
        :param count: Count of secrets/folders to create
        :type count: int
        :param words: List of available words
        :type words: list(str)
        """
        kv_per_secret = 5
        if depth == 1:
            secrets_count_to_create = count
            folders_count_to_create = 0
        else:
            secrets_count_to_create = random.randint(0, count - 1)
            folders_count_to_create = random.randint(
                1, count - secrets_count_to_create
            )
        self.logger.info("Will create %s secrets and %s folders under '%s'" %
                         (secrets_count_to_create,
                          folders_count_to_create,
                          path))
        for i_secrets in range(0, secrets_count_to_create):
            secret = {}
            for i_kv in range(0, kv_per_secret):
                secret[random.choice(words)] = random.choice(words)
            vault_client.write(path + "/" + random.choice(words), secret)
        if depth > 1:
            for i_folders in range(0, folders_count_to_create):
                self.kv_generate_tree_recursive(
                    vault_client,
                    path + "/" + random.choice(words),
                    depth - 1, count, words
                )

    def kv_generate_tree(self, vault_addr, vault_token, paths, depth):
        """
        Generate a random K/V tree under path

        :param vault_addr: Vault instance URL
        :type vault_addr: str
        :param vault_token: Vault token
        :type vault_token: str
        :param paths: List of paths under which the tree will be created
        :type paths: list(str)
        :param depth: Tree depth
        :type depth: int
        """
        if not os.path.isfile("/usr/share/dict/words"):
            raise ValueError("File '/usr/share/dict/words' containing words"
                             "doesn't exists")
        with open("/usr/share/dict/words", 'r') as fd:
            words = fd.read().splitlines()
        vault_client = self.connect_to_vault(
            vault_addr,
            vault_token
        )
        max_count = 5
        self.logger.debug("KV generate tree starting")
        for path in paths:
            self.kv_generate_tree_recursive(
                vault_client, path,
                depth, max_count, words
            )

    def run_kv_generate_tree(self):
        """
        Prepares a CLI run of kv_generate_tree
        """
        self.logger.debug("Preparing a run of kv_generate_tree")
        missing_args = utils.keys_exists_in_dict(
            self.logger, self.kwargs,
            [{"key": "vault_addr", "exc": [None, '']},
             {"key": "vault_token", "exc": [None, False]}]
        )
        if len(missing_args):
            raise ValueError(
                "Following arguments are missing %s" %
                [k['key'].replace("_", "-") for k in missing_args]
            )
        self.kv_generate_tree(
            self.kwargs["vault_addr"],
            self.kwargs["vault_token"],
            self.kwargs["generate_tree"],
            self.kwargs["depth"]
        )

    def run_kv_count(self):
        """
        Prepares a CLI run of kv_count
        """
        self.logger.debug("Preparing run of kv_count")
        missing_args = utils.keys_exists_in_dict(
            self.logger, self.kwargs,
            [{"key": "vault_addr", "exc": [None, '']},
             {"key": "vault_token", "exc": [None, False]}]
        )
        if len(missing_args):
            raise ValueError(
                "Following arguments are missing %s" %
                [k['key'].replace("_", "-") for k in missing_args]
            )
        self.kv_count(
            self.kwargs["vault_addr"],
            self.kwargs["vault_token"],
            self.kwargs["count"],
            self.kwargs["exclude"] if self.kwargs["exclude"] else []
        )

    def run_kv_find_duplicates(self):
        """
        Prepares a CLI run of kv_find_duplicates
        """
        self.logger.debug("Preparing run of kv_find_duplicates")
        missing_args = utils.keys_exists_in_dict(
            self.logger, self.kwargs,
            [{"key": "vault_addr", "exc": [None, '']},
             {"key": "vault_token", "exc": [None, False]}]
        )
        if len(missing_args):
            raise ValueError(
                "Following arguments are missing %s" %
                [k['key'].replace("_", "-") for k in missing_args]
            )
        self.kv_find_duplicates(
            self.kwargs["vault_addr"],
            self.kwargs["vault_token"],
            self.kwargs["find_duplicates"],
            self.kwargs["exclude"] if self.kwargs["exclude"] else []
        )

    def run_kv_search(self):
        """
        Prepares a CLI run of kv_search
        """
        self.logger.debug("Preparing run of kv_search")
        missing_args = utils.keys_exists_in_dict(
            self.logger, self.kwargs,
            [{"key": "vault_addr", "exc": [None, '']},
             {"key": "vault_token", "exc": [None, False]}]
        )
        if len(missing_args):
            raise ValueError(
                "Following arguments are missing %s" %
                [k['key'].replace("_", "-") for k in missing_args]
            )
        self.kv_search(
            self.kwargs["vault_addr"],
            self.kwargs["vault_token"],
            self.kwargs["search"],
            self.kwargs["include"] if self.kwargs["include"] else [],
            self.kwargs["exclude"] if self.kwargs["exclude"] else []
        )

    def run_kv_secrets_tree(self):
        """
        Prepares a CLI run of kv_secrets_tree
        """
        self.logger.debug("Preparing run of kv_secrets_tree")
        missing_args = utils.keys_exists_in_dict(
            self.logger, self.kwargs,
            [{"key": "vault_addr", "exc": [None, '']},
             {"key": "vault_token", "exc": [None, False]}]
        )
        if len(missing_args):
            raise ValueError(
                "Following arguments are missing %s" %
                [k['key'].replace("_", "-") for k in missing_args]
            )
        self.kv_secrets_tree(
            self.kwargs["vault_addr"],
            self.kwargs["vault_token"],
            self.kwargs["secrets_tree"],
            self.kwargs["exclude"] if self.kwargs["exclude"] else []
        )

    def run_kv_delete(self):
        """
        Prepares a CLI run of kv_delete
        """
        self.logger.debug("Preparing run of kv_delete")
        missing_args = utils.keys_exists_in_dict(
            self.logger, self.kwargs,
            [{"key": "vault_addr", "exc": [None, '']},
             {"key": "vault_token", "exc": [None, False]}]
        )
        if len(missing_args):
            raise ValueError(
                "Following arguments are missing %s" %
                [k['key'].replace("_", "-") for k in missing_args]
            )
        self.kv_delete(
            self.kwargs["vault_addr"],
            self.kwargs["vault_token"],
            self.kwargs["delete"]
        )

    def run_kv_copy_secret(self):
        """
        Prepares a CLI run of kv_copy_secret
        """
        self.logger.debug("Preparing run of kv_copy_secret")
        missing_args = utils.keys_exists_in_dict(
            self.logger, self.kwargs,
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
        self.kv_copy_secret(
            self.kwargs["vault_addr"],
            self.kwargs["vault_token"],
            self.kwargs["vault_target_addr"],
            self.kwargs["vault_target_token"],
            self.kwargs["copy_secret"][0],
            self.kwargs["copy_secret"][1]
        )

    def run_kv_copy_path(self):
        """
        Prepares a CLI run of kv_copy_path
        """
        self.logger.debug("Preparing run of kv_copy_path")
        missing_args = utils.keys_exists_in_dict(
            self.logger, self.kwargs,
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
        self.kv_copy_path(
            self.kwargs["vault_addr"],
            self.kwargs["vault_token"],
            self.kwargs["vault_target_addr"],
            self.kwargs["vault_target_token"],
            self.kwargs["copy_path"][0],
            self.kwargs["copy_path"][1]
        )

    def run(self, kwargs):
        """
        Module entry point

        :param kwargs: Arguments parsed as a dictionary
        :type kwargs: dict
        """
        # Convert kwargs to an Object with kwargs dict as class vars
        self.kwargs = kwargs
        if not any([self.kwargs["copy_path"], self.kwargs["count"],
                    self.kwargs["copy_secret"], self.kwargs["delete"],
                    self.kwargs["find_duplicates"],
                    self.kwargs["secrets_tree"], self.kwargs["generate_tree"],
                    self.kwargs["search"]]):
            self.logger.error("One argument should be specified")
            self.subparser.print_help()
            return False
        self.dry_run = self.kwargs["dry_run"]
        self.skip_tls = self.kwargs["skip_tls"]
        self.logger.debug("Module " + self.module_name + " started")
        try:
            if self.kwargs["copy_path"]:
                self.run_kv_copy_path()
            elif self.kwargs["copy_secret"]:
                self.run_kv_copy_secret()
            elif self.kwargs["delete"]:
                self.run_kv_delete()
            elif self.kwargs["count"]:
                self.run_kv_count()
            elif self.kwargs["find_duplicates"]:
                self.run_kv_find_duplicates()
            elif self.kwargs["secrets_tree"]:
                self.run_kv_secrets_tree()
            elif self.kwargs["generate_tree"]:
                self.run_kv_generate_tree()
            elif self.kwargs["search"]:
                self.run_kv_search()
        except AttributeError as e:
            self.logger.error(str(e))
        except ValueError as e:
            self.logger.error(str(e))
