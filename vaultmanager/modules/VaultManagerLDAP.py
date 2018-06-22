import os
import yaml
import logging
try:
    from lib.VaultClient import VaultClient
    from lib.LDAPReader import LDAPReader
except ImportError:
    from vaultmanager.lib.VaultClient import VaultClient
    from vaultmanager.lib.LDAPReader import LDAPReader


class VaultManagerLDAP:
    logger = None
    subparser = None
    parsed_args = None
    arg_parser = None
    module_name = None
    base_logger = None
    conf = None
    vault_client = None
    ldap_users = None
    policies_folder = None
    user_policies_folder = None
    group_policies_folder = None
    group_policies_to_create = None
    user_policies_to_create = None

    def __init__(self, base_logger, subparsers):
        """
        :param base_logger: main class name
        :type base_logger: string
        :param subparsers: list of all subparsers
        :type subparsers: argparse.ArgumentParser.add_subparsers()
        """
        self.base_logger = base_logger
        self.logger = logging.getLogger(base_logger + "." + self.__class__.__name__)
        self.logger.debug("Initializing VaultManagerLDAP")
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
        self.subparser.add_argument("--create",
                                    help="Create policies from LDAP groups and users",
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
        if not self.parsed_args.create:
            self.logger.critical("you must specify a command")
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

    def read_configuration(self):
        self.logger.debug("Reading configuration")
        with open(os.path.join(os.environ["VAULT_POLICIES"], "policies.yml"),
                  'r') as fd:
            try:
                self.conf = yaml.load(fd)
            except yaml.YAMLError as e:
                self.logger.critical("Impossible to load conf file: " + str(e))
                return False
        self.logger.debug("Read conf: " + str(self.conf))
        return True

    def get_ldap_data(self):
        self.logger.info("Reading LDAP data")
        # base_logger, server, user, password, group_dn, user_dn
        ldap_password = \
        self.vault_client.read_secret(self.conf["general"]["ldap"]["password"])[
            "data"]["password"]
        ldap_reader = LDAPReader(self.base_logger,
                                 self.conf["general"]["ldap"]["server"],
                                 self.conf["general"]["ldap"]["username"],
                                 ldap_password,
                                 self.conf["general"]["ldap"]["group_dn"],
                                 self.conf["general"]["ldap"]["user_dn"])
        if not ldap_reader.connect_to_ldap():
            return False
        self.ldap_users = ldap_reader.get_all_users(ldap_reader.get_all_groups())
        ldap_reader.disconnect_from_ldap()
        return True

    def create_groups_policies(self):
        self.logger.info("Creating groups policies")
        ldap_groups = list(sorted(set([group for user in self.ldap_users for group in self.ldap_users[user]])))
        for read_group in self.conf["groups"]["groups_to_add"]:
            if read_group not in ldap_groups:
                self.logger.warning("Group " + read_group +
                                    " in conf file 't been found in LDAP "
                                    "groups. Default conf file. "
                                    "The default group policy will be created "
                                    "anyway.")
        with open(os.path.join(self.policies_folder, self.conf["general"]["group"]["default_policy"]), 'r') as fd:
            default_policy = fd.read()
        for group in self.conf["groups"]["groups_to_add"]:
            policy_file = os.path.join(self.group_policies_folder,
                                       group + ".hcl")
            self.group_policies_to_create.append(policy_file)
            if os.path.isfile(policy_file):
                self.logger.info(
                    "Policy " + os.path.join(self.policies_folder,
                                             group + ".hcl") +
                    " already exists and will not be overwritten")
            else:
                with open(policy_file, 'w+') as fd:
                    fd.write(default_policy.replace("{{GROUP_NAME}}", group))
                    self.logger.info("Default policy for " + group + " written")

    def create_users_policies(self):
        self.logger.info("Creating user policies")
        with open(os.path.join(self.policies_folder, self.conf["general"]["user"]["default_policy"]), 'r') as fd:
            default_policy = fd.read()
        for user in self.ldap_users:
            if len(set(self.conf["groups"]["groups_to_add"]).intersection(
                    self.ldap_users[user])):
                policy_file = os.path.join(self.user_policies_folder,
                                           user + ".hcl")
                self.user_policies_to_create.append(policy_file)
                if os.path.isfile(policy_file):
                    self.logger.info(
                        "Configuration for user " + user +
                        " already exists and will not be overwritten")
                else:
                    with open(policy_file, 'w+') as fd:
                        fd.write(default_policy.replace("{{USER_NAME}}", user))
                        self.logger.info(
                            "Configuration for user " + user + " created")

    def deleting_previous_policies(self):
        self.logger.debug("Deleting policies of previously existing LDAP users")
        print(self.group_policies_to_create)
        print(self.user_policies_to_create)
        for file in os.listdir(self.group_policies_folder):
            policy_path = os.path.join(self.group_policies_folder, file)
            if policy_path not in self.group_policies_to_create:
                self.logger.debug("Deleting group policy: " + policy_path)
                os.remove(policy_path)
        for file in os.listdir(self.user_policies_folder):
            policy_path = os.path.join(self.user_policies_folder, file)
            if policy_path not in self.user_policies_to_create:
                self.logger.debug("Deleting user policy: " + policy_path)
                os.remove(policy_path)

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
        self.policies_folder = os.environ["VAULT_POLICIES"]
        self.user_policies_folder = os.path.join(self.policies_folder, "user")
        self.group_policies_folder = os.path.join(self.policies_folder, "group")
        self.group_policies_to_create = []
        self.user_policies_to_create = []
        if not self.read_configuration():
            return False
        self.vault_client = VaultClient(self.base_logger)
        self.vault_client.authenticate()
        if self.parsed_args.create:
            if not self.get_ldap_data():
                return False
            self.create_groups_policies()
            self.create_users_policies()
            self.deleting_previous_policies()



