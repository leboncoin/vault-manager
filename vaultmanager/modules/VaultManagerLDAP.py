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
    """
    LDAP Module
    """
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
        self.subparser.add_argument(
            "--list-groups", action='store_true', help="List LDAP groups"
        )
        self.subparser.add_argument(
            "--create-policies", action='store_true',
            help="Create policies from LDAP groups and users"
        )
        self.subparser.add_argument(
            "--manage-ldap-groups", nargs='?', metavar="LDAP_mount_point",
            help="Create LDAP groups in Vault with associated policies at specified mount point"
        )
        self.subparser.add_argument(
            "--manage-ldap-users", nargs='?', metavar="LDAP_mount_point",
            help="Create LDAP users in Vault with associated policies and groups at specified mount point"
        )
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
        args_false_count = [self.parsed_args.create_policies,
                            self.parsed_args.manage_ldap_groups,
                            self.parsed_args.manage_ldap_users,
                            self.parsed_args.list_groups].count(False)
        args_none_count = [self.parsed_args.create_policies,
                           self.parsed_args.manage_ldap_groups,
                           self.parsed_args.manage_ldap_users,
                           self.parsed_args.list_groups].count(None)
        no_args_count = args_false_count + args_none_count
        if no_args_count in [4, 5]:
            self.logger.critical("you must specify a command")
            return False
        return True

    def check_env_vars(self):
        """
        Check if all needed env vars are set

        :return: bool
        """
        self.logger.debug("Checking env variables")
        needed_env_vars = ["VAULT_ADDR", "VAULT_TOKEN", "VAULT_CONFIG"]
        if not all(env_var in os.environ for env_var in needed_env_vars):
            self.logger.critical("The following env vars must be set")
            self.logger.critical(str(needed_env_vars))
            return False
        self.logger.debug("All env vars are set")
        if not os.path.isdir(os.environ["VAULT_CONFIG"]):
            self.logger.critical(
                os.environ["VAULT_CONFIG"] + " is not a valid folder")
            return False
        self.logger.info("Vault address: " + os.environ["VAULT_ADDR"])
        self.logger.info("Vault config folder: " + os.environ["VAULT_CONFIG"])
        return True

    def read_configuration(self):
        """
        Read the configuration file
        """
        self.logger.debug("Reading configuration")
        with open(os.path.join(self.policies_folder, "policies.yml"),
                  'r') as fd:
            try:
                self.conf = yaml.load(fd)
            except yaml.YAMLError as e:
                self.logger.critical("Impossible to load conf file: " + str(e))
                return False
        self.logger.debug("Read conf: " + str(self.conf))
        return True

    def get_ldap_data(self):
        """
        Fetch users and groups from LDAP
        """
        self.logger.info("Reading LDAP data")
        # base_logger, server, user, password, group_dn, user_dn
        try:
            ldap_password = self.vault_client.read_string_with_secret(
                self.conf["general"]["ldap"]["password"]
            )
        except TypeError as e:
            raise Exception("LDAP password does not exists in Vault")
        ldap_reader = LDAPReader(self.base_logger,
                                 self.conf["general"]["ldap"]["server"],
                                 self.conf["general"]["ldap"]["username"],
                                 ldap_password,
                                 self.conf["general"]["ldap"]["group_dn"],
                                 self.conf["general"]["ldap"]["user_dn"])
        if not ldap_reader.connect_to_ldap():
            return False
        self.ldap_users = ldap_reader.get_all_users(ldap_reader.get_all_groups())
        self.logger.debug("Users found: " + str(self.ldap_users))
        ldap_reader.disconnect_from_ldap()
        return True

    def create_groups_policies(self):
        """
        Create a policy for each group
        """
        self.logger.info("Creating groups policies")
        ldap_groups = list(sorted(set([group for user in self.ldap_users for group in self.ldap_users[user]])))
        for read_group in self.conf["groups"]["groups_to_add"]:
            if read_group not in ldap_groups:
                self.logger.warning("Group " + read_group +
                                    " in conf file 't been found in LDAP "
                                    "groups. Default conf file. "
                                    "The default group policy will be created "
                                    "anyway.")
        with open(
                os.path.join(
                    self.policies_folder,
                    self.conf["general"]["group"]["default_policy"]
                ), 'r') as fd:
            default_policy = fd.read()
        for group in self.conf["groups"]["groups_to_add"]:
            policy_file = os.path.join(self.group_policies_folder,
                                       group + ".hcl")
            self.group_policies_to_create.append(policy_file)
            if os.path.isfile(policy_file):
                self.logger.info(
                    "Policy for group " + group +
                    " already exists and will not be overwritten"
                )
            else:
                with open(policy_file, 'w+') as fd:
                    fd.write(default_policy.replace("{{GROUP_NAME}}", group))
                    self.logger.info("Default policy for " + group + " written")

    def create_users_policies(self):
        """
        Create policies for each LDAP user
        """
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
                        "Policy for user " + user +
                        " already exists and will not be overwritten")
                else:
                    with open(policy_file, 'w+') as fd:
                        fd.write(default_policy.replace("{{USER_NAME}}", user))
                        self.logger.info(
                            "Policy for user " + user + " created")

    def deleting_previous_policies(self):
        """
        Deleting policies of non existing LDAP users
        """
        self.logger.debug("Deleting policies of previously existing LDAP users")
        for file in os.listdir(self.group_policies_folder):
            policy_path = os.path.join(self.group_policies_folder, file)
            if policy_path not in self.group_policies_to_create:
                self.logger.info("Deleting group policy: " + policy_path)
                os.remove(policy_path)
        for file in os.listdir(self.user_policies_folder):
            policy_path = os.path.join(self.user_policies_folder, file)
            if policy_path not in self.user_policies_to_create:
                self.logger.info("Deleting user policy: " + policy_path)
                os.remove(policy_path)

    def manage_groups_in_vault_ldap_conf(self):
        """
        Manage groups in Vault LDAP configuration
        """
        self.logger.debug("Managing groups to Vault LDAP configuration")
        raw_vault_ldap_groups = self.vault_client.list('/auth/ldap/groups')
        existing_groups = []
        if len(raw_vault_ldap_groups):
            existing_groups = raw_vault_ldap_groups["keys"]
        for group in self.conf["groups"]["groups_to_add"]:
            if group in existing_groups:
                existing_groups.remove(group)
            policies = ["group_" + group + "_policy"]
            if "root" in self.conf["general"]["group"] and \
                    group in self.conf["general"]["group"]["root"]:
                policies.append("root")
            self.logger.info("Adding polices %s to group %s" %
                             (str(policies), group))
            self.vault_client.write(
                "/auth/ldap/groups/" + group,
                {"policies": self.list_to_string(policies)}
            )
        self.logger.debug("Removing groups %s from Vault LDAP conf" %
                          str(existing_groups))
        for group in existing_groups:
            self.logger.info("Removing group %s from Vault LDAP conf" % group)
            self.vault_client.delete('/auth/ldap/groups/' + group)

    def manage_users_in_vault_ldap_conf(self):
        """
        Manage users in Vault LDAP configuration
        """
        self.logger.debug("Managing users to Vault LDAP configuration")
        raw_vault_ldap_users = self.vault_client.list('/auth/ldap/users')
        self.logger.debug("Users found: " + str(raw_vault_ldap_users))
        existing_users = []
        if len(raw_vault_ldap_users):
            existing_users = raw_vault_ldap_users["keys"]

        for user in self.ldap_users:
            groups_of_user = list(
                set(self.conf["groups"]["groups_to_add"]).intersection(
                    self.ldap_users[user]))
            if not len(groups_of_user):
                continue
            if user in existing_users:
                existing_users.remove(user)
            policies = ["user_" + user + "_policy"]
            if "root" in self.conf["general"]["group"] and \
                    user in self.conf["general"]["user"]["root"]:
                policies.append("root")
            self.logger.info("Adding polices %s to user %s" %
                             (str(policies), user))
            self.logger.info("Adding groups %s to user %s" %
                             (str(groups_of_user), user))
            self.vault_client.write(
                "/auth/ldap/users/" + user,
                {
                    "policies": self.list_to_string(policies),
                    "groups": self.list_to_string(groups_of_user)
                }
            )
            print(self.list_to_string(policies))
            print(self.list_to_string(groups_of_user))
        self.logger.debug("Removing users %s from Vault LDAP conf" %
                          str(existing_users))
        for user in existing_users:
            self.logger.info("Removing user %s from Vault LDAP conf" % user)
            self.vault_client.delete('/auth/ldap/users/' + user)

    def list_to_string(self, list_to_serialize):
        """
        Transform a list to a string

        :param list_to_serialize: list to transform
        :type list_to_serialize: list

        :return: str
        """
        self.logger.debug("serializing list: " + str(list_to_serialize))
        return str(list_to_serialize)\
            .replace("[", "")\
            .replace("]", "")\
            .replace(" ", "")

    def list_ldap_groups(self):
        """
        Display LDAP groups
        """
        self.logger.debug("Displaying LDAP groups")
        groups = []
        for user in self.ldap_users:
            for group in self.ldap_users[user]:
                if group not in groups:
                    groups.append(group)
        self.logger.info(str(sorted(groups)))

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
            self.subparser.print_help()
            return False
        if not self.check_env_vars():
            return False
        self.policies_folder = os.path.join(os.environ["VAULT_CONFIG"],
                                            "policies")
        self.user_policies_folder = os.path.join(self.policies_folder, "user")
        self.group_policies_folder = os.path.join(self.policies_folder, "group")
        self.group_policies_to_create = []
        self.user_policies_to_create = []
        if not self.read_configuration():
            return False
        self.vault_client = VaultClient(
            self.base_logger,
            self.parsed_args.dry_run
        )
        self.vault_client.authenticate()
        if not self.get_ldap_data():
            return False
        if self.parsed_args.list_groups:
            self.list_ldap_groups()
            return True
        if self.parsed_args.create_policies:
            self.logger.info("Creating LDAP policies")
            self.create_groups_policies()
            self.create_users_policies()
            self.deleting_previous_policies()
        if self.parsed_args.manage_ldap_groups:
            self.logger.info("Managing groups in Vault LDAP '%s' config" %
                             self.parsed_args.manage_ldap_groups)
            self.manage_groups_in_vault_ldap_conf()
        if self.parsed_args.manage_ldap_users:
            self.logger.info("Managing users in Vault LDAP '%s' config" %
                             self.parsed_args.manage_ldap_users)
            self.manage_users_in_vault_ldap_conf()


