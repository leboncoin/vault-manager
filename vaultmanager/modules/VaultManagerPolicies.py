import os
import glob
import logging
from collections import namedtuple
try:
    from lib.VaultClient import VaultClient
    import lib.utils as utils
except ImportError:
    from vaultmanager.lib.VaultClient import VaultClient
    import vaultmanager.lib.utils as utils


class VaultManagerPolicies:
    logger = None
    subparser = None
    kwargs = None
    module_name = None
    vault_client = None
    base_logger = None
    policies_folder = None

    def __init__(self, base_logger=None):
        """
        :param base_logger: main class name
        :type base_logger: string
        :param subparsers: list of all subparsers
        :type subparsers: argparse.ArgumentParser.add_subparsers()
        """
        self.base_logger = base_logger
        if base_logger:
            self.logger = logging.getLogger(base_logger + "." + self.__class__.__name__)
        else:
            self.logger = logging.getLogger()
        self.logger.debug("Initializing VaultManagerPolicies")

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
        self.subparser.add_argument(
            "--pull", action='store_true',
            help="Pull distant policies from Vault"
        )
        self.subparser.add_argument(
            "--push", action='store_true', help="Push local policies to Vault"
        )
        self.subparser.set_defaults(module_name=self.module_name)

    def check_args_integrity(self):
        """
        Checking provided arguments integrity
        """
        self.logger.debug("Checking arguments integrity")
        if all(self.kwargs.pull, self.kwargs.push):
            self.logger.critical("push and pull args cannot "
                                 "be specified at the same time")
            return False
        elif not any(self.kwargs.pull, self.kwargs.push):
            self.logger.critical("You must specify pull or push")
            return False
        return True

    def policies_pull(self):
        """
        Pull policies from vault
        """
        self.logger.info("Pulling Policies from Vault")
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
            # create the parent folder policy if doest not exists (user, etc...)
            policy_folder = os.path.join(self.policies_folder, splitted[0])
            if not os.path.isdir(policy_folder):
                self.logger.debug("Folder " + policy_folder +
                                  " doest not exists, creating...")
                os.makedirs(policy_folder)
            # create the policy file
            policy_path = os.path.join(policy_folder, splitted[1] + ".hcl")
            with open(policy_path, 'w+') as fd:
                fd.write(self.vault_client.policy_get(policy))
                self.logger.info("Policy " + policy_path + " saved")
        self.logger.info("Policies fetched in policies folder")

    def policies_push(self):
        """
        Push all policies from policies folder to Vault
        """
        self.logger.info("Pushing Policies to Vault")
        self.logger.debug("Push all policies")
        distant_policies = self.vault_client.policy_list()
        local_policies = []
        # Building local policies list
        for policy_file in glob.iglob(os.path.join(self.policies_folder,
                                                   "*/*.hcl"), recursive=True):
            name = os.path.splitext(os.path.basename(policy_file))[0]
            prefix = policy_file.split(os.sep)[-2]
            self.logger.debug("Local policy %s - prefix: %s - name: %s found"
                              % (policy_file, prefix, name))
            with open(policy_file, 'r') as fd:
                local_policies.append({"name": prefix + "_" + name + "_policy",
                                       "content": fd.read()})
        # Removing distant policies which doesn't exists locally
        for distant_policy in distant_policies:
            if distant_policy not in [pol["name"] for pol in local_policies]:
                self.logger.info("Removing distant policy " + distant_policy)
                self.vault_client.policy_delete(distant_policy)
        # Push local policies
        for policy in local_policies:
            self.vault_client.policy_set(policy_name=policy["name"],
                                         policy_content=policy["content"])
            if policy["name"] in distant_policies:
                self.logger.info("Policy %s has been updated" % policy["name"])
            else:
                self.logger.info("Policy %s has been created" % policy["name"])
        self.logger.info("Policies pushed to Vault")

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
        self.logger.debug("Vault config folder: %s" % self.kwargs.vault_config)
        self.policies_folder = os.path.join(
            self.kwargs.vault_config, "policies"
        )
        if not os.path.isdir(self.policies_folder):
            os.mkdir(self.policies_folder)
        self.vault_client = VaultClient(
            self.base_logger,
            vault_addr=self.kwargs.vault_addr,
            dry=self.kwargs.dry_run,
            skip_tls=self.kwargs.skip_tls
        )
        self.vault_client.authenticate()
        if self.kwargs.pull:
            self.policies_pull()
        if self.kwargs.push:
            self.policies_push()
