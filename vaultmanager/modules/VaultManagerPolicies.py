import os
import glob
import logging
try:
    from lib.VaultClient import VaultClient
except ImportError:
    from vaultmanager.lib.VaultClient import VaultClient


class VaultManagerPolicies:
    logger = None
    subparser = None
    parsed_args = None
    arg_parser = None
    module_name = None
    vault_client = None
    base_logger = None

    def __init__(self, base_logger, subparsers):
        """
        :param base_logger: main class name
        :type base_logger: string
        :param subparsers: list of all subparsers
        :type subparsers: argparse.ArgumentParser.add_subparsers()
        """
        self.base_logger = base_logger
        self.logger = logging.getLogger(base_logger + "." + self.__class__.__name__)
        self.logger.debug("Initializing VaultManagerPolicies")
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
        self.subparser = \
            subparsers.add_parser(self.module_name,
                                  help=self.module_name + ' management')
        self.subparser.add_argument("--pull",
                                    help="Pull local policies to Vault",
                                    action='store_true')
        self.subparser.add_argument("--push",
                                    help="Push local policies to Vault",
                                    action='store_true')
        self.subparser.set_defaults(module_name=self.module_name)

    def get_subparser(self):
        """
        Module subparser getter

        :return: argparse.ArgumentParser.add_subparsers().add_parser()
        """
        return self.subparser

    def check_args_integrity(self):
        """
        Checking provided arguments integrity
        """
        self.logger.debug("Checking arguments integrity")
        if self.parsed_args.pull and self.parsed_args.push:
            self.logger.critical("push and pull args cannot "
                                 "be specified at the same time")
            return False
        elif not self.parsed_args.pull and not self.parsed_args.push:
            self.logger.critical("You must specify pull or push")
            return False
        return True

    def check_env_vars(self):
        """
        Check if all needed env vars are set

        :return: bool
        """
        self.logger.debug("Checking env variables")
        needed_env_vars = ["VAULT_ADDR", "VAULT_TOKEN", "VAULT_POLICIES"]
        if not all(env_var in os.environ for env_var in needed_env_vars):
            self.logger.critical("The following env vars must be set")
            self.logger.critical(str(needed_env_vars))
            return False
        self.logger.debug("All env vars are set")
        if not os.path.isdir(os.environ["VAULT_POLICIES"]):
            self.logger.critical(
                os.environ["VAULT_POLICIES"] + " is not a valid folder")
            return False
        return True

    def pull_policies(self):
        """
        Pull policies from vault
        """
        self.logger.debug("Pulling policies")
        distant_policies = self.vault_client.policy_list()
        self.logger.info("Distant policies found:" + str(distant_policies))
        for policy in distant_policies:
            # policy name will always be 'type_name_policy'
            splitted = policy.split("_")
            if len(splitted) != 3 or splitted[2] != "policy":
                self.logger.warning("Policy " + policy +
                                    " does not match policy name pattern "
                                    "and will not be pulled")
                continue
            if not os.path.isdir(os.path.join(os.environ["VAULT_POLICIES"],
                                              splitted[0])):
                os.makedirs(os.path.join(os.environ["VAULT_POLICIES"],
                                         splitted[0]))
            with open(os.path.join(os.environ["VAULT_POLICIES"],
                                   splitted[0], splitted[1] + ".hcl"),
                      'w+') as fd:
                fd.write(self.vault_client.policy_get(policy))

    def push_policies(self):
        """
        Push all policies from policies folder to Vault
        """
        self.logger.debug("Push all policies")
        distant_policies = self.vault_client.policy_list()
        local_policies = []
        # Building local policies list
        for policy_file in glob.iglob(os.path.join(os.environ["VAULT_POLICIES"],
                                                   "**/*.hcl"), recursive=True):
            name = os.path.splitext(os.path.basename(policy_file))[0]
            prefix = policy_file.split(os.sep)[-2]
            self.logger.debug("Local policy " + policy_file +
                              " - prefix: " + prefix +
                              " - name: " + name + " found")
            with open(policy_file, 'r') as fd:
                local_policies.append({"name": prefix + "_" + name + "_policy",
                                       "content": fd.read()})
        # Removing distant policies which doesn't exists locally
        for distant_policy in distant_policies:
            if distant_policy not in [pol["name"] for pol in local_policies]:
                self.logger.debug("Removing distant policy " + distant_policy)
                self.vault_client.policy_delete(distant_policy)
        # Push local policies
        for policy in local_policies:
            if policy["name"] in distant_policies:
                self.logger.debug("Policy " + policy["name"] +
                                  " will be updated")
            else:
                self.logger.debug("Policy " + policy["name"] +
                                  " will be created")
            self.vault_client.policy_set(policy_name=policy["name"],
                                         policy_content=policy["content"])

    def run(self, arg_parser, parsed_args):
        """
        Module entry point

        :param arg_parser: Arguments parser instance
        :param parsed_args: Arguments parsed fir this module
        :type parsed_args: argparse.ArgumentParser.parse_args()
        """
        self.parsed_args = parsed_args
        self.arg_parser = arg_parser
        self.logger.debug("Module " + self.module_name + " started")
        if not self.check_args_integrity():
            self.arg_parser.print_help()
            return False
        if not self.check_env_vars():
            return False
        self.vault_client = VaultClient(self.base_logger)
        self.vault_client.authenticate()
        if self.parsed_args.pull:
            self.pull_policies()
        if self.parsed_args.push:
            self.push_policies()
