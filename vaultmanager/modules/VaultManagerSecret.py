import os
import logging
import yaml
from collections import OrderedDict
from collections import namedtuple
try:
    from lib.VaultClient import VaultClient
    from lib.VaultSecretEngine import VaultSecretEngine
    import lib.utils as utils
except ImportError:
    from vaultmanager.lib.VaultClient import VaultClient
    from vaultmanager.lib.VaultSecretEngine import VaultSecretEngine
    import vaultmanager.lib.utils as utils


class VaultManagerSecret:
    logger = None
    base_logger = None
    subparser = None
    parsed_args = None
    arg_parser = None
    module_name = None
    vault_client = None
    conf = None
    distant_secrets_engines = None
    local_secrets_engines = None

    def __init__(self, base_logger=None):
        """
        :param base_logger: main class name
        :type base_logger: string
        """
        self.base_logger = base_logger
        if base_logger:
            self.logger = logging.getLogger(base_logger + "." + self.__class__.__name__)
        else:
            self.logger = logging.getLogger()
        self.logger.debug("Initializing VaultManagerLDAP")

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
                                    help="Push secrets engines to Vault")
        self.subparser.set_defaults(module_name=self.module_name)

    def check_args_integrity(self):
        """
        Checking provided arguments integrity
        """
        self.logger.debug("Checking arguments integrity")
        args_false_count = [self.kwargs.push].count(False)
        args_none_count = [self.kwargs.push].count(None)
        no_args_count = args_false_count + args_none_count
        if no_args_count in [1]:
            self.logger.critical("you must specify a command")
            return False
        return True

    def read_configuration(self):
        """
        Read configuration file
        """
        self.logger.debug("Reading configuration")
        with open(os.path.join(self.kwargs.vault_config,
                               "secrets-engines.yml"), 'r') as fd:
            try:
                self.conf = yaml.safe_load(fd)
            except yaml.YAMLError as e:
                self.logger.critical("Impossible to load conf file: " + str(e))
                return False
        self.logger.debug("Read conf: " + str(self.conf))
        return True

    def get_distant_secrets_engines(self):
        """
        Fetch distant auth methods
        """
        self.logger.debug("Fetching distant secrets engines")
        self.distant_secrets_engines = []
        raw = self.vault_client.secret_list()
        for secret_engine in raw:
            self.distant_secrets_engines.append(
                VaultSecretEngine(
                    type=raw[secret_engine]["type"],
                    path=(raw[secret_engine]["path"] if 'path' in raw[
                        secret_engine] else secret_engine),
                    description=raw[secret_engine]["description"],
                    tuning=OrderedDict(sorted(raw[secret_engine]["config"].items()))
                )
            )
        self.logger.debug("Distant secrets engines found")
        for elem in self.distant_secrets_engines:
            self.logger.debug(elem)

    def get_local_secrets_engines(self):
        """
        Fetch local secrets engines
        """
        self.logger.debug("Fetching local secrets engines")
        self.local_secrets_engines = []
        for secret_engine in self.conf["secrets-engines"]:
            secret_config = None
            if "secret_config" in secret_engine:
                secret_config = OrderedDict(sorted(secret_engine["secret_config"].items()))
            self.local_secrets_engines.append(
                VaultSecretEngine(
                    type=secret_engine["type"],
                    path=secret_engine["path"],
                    description=secret_engine["description"],
                    tuning=OrderedDict(sorted(secret_engine["tuning"].items())),
                    secret_config=secret_config
                )
            )
        self.logger.debug("Local secrets engines found")
        for elem in self.local_secrets_engines:
            self.logger.debug(elem)

    def disable_distant_secrets_engines(self):
        """
        Disable secrets engines not found in conf
        """
        self.logger.debug("Disabling secrets engines")
        for secret_engine in self.distant_secrets_engines:
            if secret_engine not in self.local_secrets_engines:
                self.logger.info("Disabling: " + str(secret_engine))
                self.vault_client.secret_disable(secret_engine.path)

    def enable_distant_secrets_engines(self):
        """
        Enable secrets engines found in conf
        """
        self.logger.debug("Enabling secrets engines")
        for secret_engine in self.local_secrets_engines:
            if secret_engine not in self.distant_secrets_engines:
                self.logger.info("Enabling: " + str(secret_engine))
                self.vault_client.secret_enable(
                    secret_type=secret_engine.type,
                    path=secret_engine.path,
                    description=secret_engine.description
                )

    def tune_secret_engine(self, local_secret_engine, distant_secret_engine):
        """
        Tune a secret engine

        :param local_secret_engine: Local auth method
        :type local_secret_engine: VaultAuthMethod
        :param distant_secret_engine: Distant auth method
        :type distant_secret_engine: VaultAuthMethod
        """
        self.logger.debug("Local tuning for: " + local_secret_engine.path)
        self.logger.debug("Description: " + local_secret_engine.description)
        self.logger.debug("Hash: " + local_secret_engine.get_tuning_hash())
        self.logger.debug("Tuning: " + str(local_secret_engine.tuning))

        self.logger.debug("Distant tuning for: " + distant_secret_engine.path)
        self.logger.debug("Description: " + distant_secret_engine.description)
        self.logger.debug("Hash: " + distant_secret_engine.get_tuning_hash())
        self.logger.debug("Tuning: " + str(distant_secret_engine.tuning))
        self.vault_client.secret_tune(
            local_secret_engine.path,
            default_lease_ttl=local_secret_engine.tuning["default_lease_ttl"],
            max_lease_ttl=local_secret_engine.tuning["max_lease_ttl"],
            description=local_secret_engine.description
        )

    def find_secrets_engines_to_tune(self):
        """
        Identify secrets engines where a tuning is needed
        """
        self.logger.debug("Tuning secrets engines")
        for distant_secret in self.distant_secrets_engines:
            for local_secret in self.local_secrets_engines:
                if distant_secret == local_secret:
                    distant_tuning_hash = distant_secret.get_tuning_hash()
                    local_tuning_hash = local_secret.get_tuning_hash()
                    self.logger.debug("Hashs for %s/" % distant_secret.path)
                    self.logger.debug("Local: " + local_tuning_hash)
                    self.logger.debug("Distant: " + distant_tuning_hash)
                    if distant_tuning_hash != local_tuning_hash:
                        self.logger.info("The secret engine %s will be tuned" %
                                         local_secret.path)
                        self.tune_secret_engine(local_secret, distant_secret)
                    else:
                        self.logger.debug("The secret engine %s will not be tuned" %
                                          local_secret.path)

    def secret_push(self):
        """
        Push secrets engines configuration to Vault
        """
        self.logger.info("Pushing secret engines to Vault")
        self.read_configuration()
        self.get_distant_secrets_engines()
        self.get_local_secrets_engines()
        for secret_engine in self.local_secrets_engines:
            if secret_engine in self.distant_secrets_engines:
                self.logger.debug("Secret engine remaining unchanged " +
                                  str(secret_engine))
        if "secret-engines-deletion" in self.conf and \
                self.conf["secret-engines-deletion"]:
            self.disable_distant_secrets_engines()
        self.enable_distant_secrets_engines()
        self.get_distant_secrets_engines()
        self.logger.info("Secrets engines successfully pushed to Vault")
        self.logger.info("Tuning secrets engines")
        self.find_secrets_engines_to_tune()
        self.logger.info("Secret engines successfully tuned")

    def run(self, kwargs):
        """
        Module entry point

        :param kwargs: Arguments parsed
        :type kwargs: dict
        """
        # Convert kwargs to an Object with kwargs dict as class vars
        self.kwargs = namedtuple("KwArgs", kwargs.keys())(*kwargs.values())
        self.logger.debug("Module " + self.module_name + " started")
        if not self.check_args_integrity():
            self.subparser.print_help()
            return False
        missing_args = utils.keys_exists_in_dict(
            self.logger, dict(self.kwargs._asdict()),
            [{"key": "vault_addr", "exc": [None, '']},
             {"key": "vault_token", "exc": [None, False]},
             {"key": "vault_config", "exc": [None, False, '']}]
        )
        if len(missing_args):
            raise ValueError(
                "Following arguments are missing %s\n" % [
                    k['key'].replace("_", "-") for k in missing_args]
            )
        self.vault_client = VaultClient(
            self.base_logger,
            vault_addr=self.kwargs.vault_addr,
            dry=self.kwargs.dry_run,
            skip_tls=self.kwargs.skip_tls
        )
        self.vault_client.authenticate()
        if self.kwargs.push:
            self.secret_push()
