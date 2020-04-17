import os
import yaml
import logging
import re
from jinja2 import Template
from collections import namedtuple

try:
    from lib.VaultClient import VaultClient
    from lib.LDAPReader import LDAPReader
    import lib.utils as utils
except ImportError:
    from vaultmanager.lib.VaultClient import VaultClient
    from vaultmanager.lib.LDAPReader import LDAPReader
    import vaultmanager.lib.utils as utils


class VaultManagerLDAP:
    """
    LDAP Module
    """
    logger = None
    subparser = None
    kwargs = None
    module_name = None
    base_logger = None
    conf = None
    ldap_conf = None
    vault_client = None
    ldap_users = None
    ldap_kubernetes_groups = None
    policies_folder = None
    user_policies_folder = None
    group_policies_folder = None
    kubernetes_policies_folder = None
    group_policies_to_create = None
    kubernetes_policies_to_create = None
    user_policies_to_create = None

    def __init__(self, base_logger=None):
        """
        :param base_logger: main class name
        :type base_logger: string
        """
        self.base_logger = base_logger
        if base_logger:
            self.logger = logging.getLogger(
                base_logger + "." + self.__class__.__name__)
        else:
            self.logger = logging.getLogger()
        self.logger.debug("Initializing VaultManagerLDAP")

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
            dry=self.kwargs.dry_run,
            vault_addr=vault_addr,
            skip_tls=self.kwargs.skip_tls
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
            help="""Create LDAP groups in Vault with associated
            policies at specified mount point"""
        )
        self.subparser.add_argument(
            "--manage-ldap-users", nargs='?', metavar="LDAP_mount_point",
            help="""Create LDAP users in Vault with associated
             policies and groups at specified mount point"""
        )
        self.subparser.add_argument(
            "--create-groups-secrets", nargs='?',
            metavar="groups_secrets_folder",
            help="Create a folder for each group in <groups_secrets_folder>"
        )
        self.subparser.add_argument(
            "--create-users-secrets", nargs='?',
            metavar="users_secrets_folder",
            help="Create a folder for each user in <users_secrets_folder>"
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
        args_false_count = [self.kwargs.create_policies,
                            self.kwargs.manage_ldap_groups,
                            self.kwargs.manage_ldap_users,
                            self.kwargs.list_groups,
                            self.kwargs.create_groups_secrets,
                            self.kwargs.create_users_secrets].count(False)
        args_none_count = [self.kwargs.create_policies,
                           self.kwargs.manage_ldap_groups,
                           self.kwargs.manage_ldap_users,
                           self.kwargs.list_groups,
                           self.kwargs.create_groups_secrets,
                           self.kwargs.create_users_secrets].count(None)
        no_args_count = args_false_count + args_none_count
        if no_args_count in [6, 7]:
            self.logger.critical("you must specify a command")
            return False
        return True

    def read_configuration(self):
        """
        Read the policies configuration file
        """
        self.logger.debug("Reading configuration")
        with open(os.path.join(self.policies_folder, "policies.yml"),
                  'r') as fd:
            try:
                self.conf = yaml.safe_load(fd)
            except yaml.YAMLError as e:
                self.logger.critical("Impossible to load conf file: " + str(e))
                return False
        self.logger.debug("Read conf: " + str(self.conf))
        return True

    def read_ldap_configuration(self):
        """
        Read the LDAP configuration file
        """
        self.logger.debug("Reading LDAP configuration file")
        with open(os.path.join(self.kwargs.vault_config, "ldap.yml"),
                  'r') as fd:
            try:
                self.ldap_conf = yaml.safe_load(fd)
            except yaml.YAMLError as e:
                self.logger.critical("Impossible to load LDAP conf file: %s" %
                                     str(e))
                return False
        self.logger.debug("Read LDAP conf: " + str(self.conf))
        return True

    def get_ldap_data(self):
        """
        Fetch users and groups from LDAP
        """
        self.logger.info("Reading LDAP data")
        # base_logger, server, user, password, group_dn, user_dn
        try:
            if re.search("^VAULT{{.*}}$", self.ldap_conf["ldap"]["password"]):
                ldap_password = self.vault_client.read_string_with_secret(
                    self.ldap_conf["ldap"]["password"]
                )
            elif re.search("^ENV{{.*}}$", self.ldap_conf["ldap"]["password"]):
                ldap_password = self.vault_client.read_string_with_env(
                    self.ldap_conf["ldap"]["password"]
                )
            else:
                ldap_password = self.ldap_conf["ldap"]["password"]
        except TypeError as e:
            raise Exception("LDAP password does not exists in env at %s" %
                            str(self.ldap_conf["ldap"]["password"]))
        ldap_reader = LDAPReader(self.base_logger,
                                 self.ldap_conf["ldap"]["server"],
                                 self.ldap_conf["ldap"]["username"],
                                 ldap_password,
                                 self.ldap_conf["ldap"]["kubernetes_group_dn"],
                                 self.ldap_conf["ldap"]["group_dn"],
                                 self.ldap_conf["ldap"]["user_dn"])
        if not ldap_reader.connect_to_ldap():
            return False
        self.ldap_users = ldap_reader.get_all_users(
            ldap_reader.get_all_groups())
        self.ldap_kubernetes_groups = ldap_reader.get_kubernetes_groups()
        self.logger.debug("Users found: " + str(self.ldap_users))
        ldap_reader.disconnect_from_ldap()
        return True

    def create_groups_policies(self):
        """
        Create a policy for each group
        """
        self.logger.info("Creating groups policies")
        ldap_groups = list(sorted(set(
            [group for user in self.ldap_users for group in
             self.ldap_users[user]])))
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
        with open(os.path.join(self.policies_folder,
                               self.conf["general"]["user"]["default_policy"]),
                  'r') as fd:
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

    def create_kubernetes_policies(self):
        """
        Create policies to allow kubernetes service-accounts to read secrets
        """
        self.logger.debug("creating kubernetes policies for service_accounts")
        with open(os.path.join(
                self.policies_folder,
                self.conf["general"]["kubernetes"]["default_policy"]),
                'r') as fd:
            default_policy = fd.read()

        template = Template(default_policy)

        for env in ["qa", "preprod", "prod"]:
            for group in self.ldap_kubernetes_groups:
                policy_file = os.path.join(self.kubernetes_policies_folder, env,
                                           group + ".hcl")
                self.kubernetes_policies_to_create.append(policy_file)
                if os.path.isfile(policy_file):
                    self.logger.info(
                        "Policy for kubernetes group " + group + " in env " +
                        env + " already exists and will not be overwritten")
                else:
                    with open(policy_file, 'w+') as fd:
                        fd.write(
                            template.render(GROUP=group, ENV=env))
                        self.logger.info(
                            "Policy for kubernetes group " +
                            group + "in env " + env + " created")

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

    def ldap_list_groups(self):
        """
        Method running the list-groups function of LDAP module
        Display LDAP groups
        """
        self.logger.debug("LDAP list-groups starting")
        self.logger.debug("Displaying LDAP groups")
        groups = []
        for user in self.ldap_users:
            for group in self.ldap_users[user]:
                if group not in groups:
                    groups.append(group)
        self.logger.info(str(sorted(groups)))

    def ldap_create_policies(self):
        """
        Method running the create-policies function of LDAP module
        """
        self.logger.debug("LDAP create-policies starting")
        self.logger.info("Creating LDAP policies")
        self.create_groups_policies()
        self.create_users_policies()
        self.create_kubernetes_policies()
        self.deleting_previous_policies()

    def ldap_manage_ldap_groups(self):
        """
        Method running the manage-ldap-groups function of LDAP module
        Manage groups in Vault LDAP configuration
        """
        self.logger.debug("LDAP manage-ldap-groups starting")
        self.logger.info("Managing groups in Vault LDAP '%s' config" %
                         self.kwargs.manage_ldap_groups)
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
                {
                    "policies": utils.list_to_string(
                        self.logger, policies, separator=""
                    )
                }
            )
        self.logger.debug("Removing groups %s from Vault LDAP conf" %
                          str(existing_groups))
        for group in existing_groups:
            self.logger.info("Removing group %s from Vault LDAP conf" % group)
            self.vault_client.delete('/auth/ldap/groups/' + group)

    def ldap_manage_ldap_users(self):
        """
        Method running the manage-ldap-users function of LDAP module
        Manage users in Vault LDAP configuration
        """
        self.logger.debug("LDAP manage-ldap-users starting")
        self.logger.info("Managing users in Vault LDAP '%s' config" %
                         self.kwargs.manage_ldap_users)
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
                    "policies": utils.list_to_string(self.logger, policies,
                                                     separator=""),
                    "groups": utils.list_to_string(self.logger, groups_of_user,
                                                   separator="")
                }
            )
        self.logger.debug("Removing users %s from Vault LDAP conf" %
                          str(existing_users))
        for user in existing_users:
            self.logger.info("Removing user %s from Vault LDAP conf" % user)
            self.vault_client.delete('/auth/ldap/users/' + user)
        self.logger.info("Creating k8s secrets paths for each user")
        self.create_kubernetes_policies()

    def find_ldap_group(self, user, group_regex):
        """
        Find a group matching a regex
        """
        ft = []
        for group in self.ldap_users[user]:
            match = re.match(group_regex, group)
            if match:
                ft.extend([g for g in match.groups() if g is not None])

        if len(ft) == 0:
            return ""
        return ",".join(ft)

    def ldap_create_groups_secrets(self):
        """
        Method running the create-groups-secrets function of LDAP module
        Create a secret folder for each LDAP group under specified path
        """
        self.logger.debug("LDAP create-groups-secrets starting")
        self.logger.info("Creating groups folders under secret path '/%s'" %
                         self.kwargs.create_groups_secrets)
        self.logger.debug("Creating groups secrets under %s" %
                          self.kwargs.create_groups_secrets)
        existing_folders = self.vault_client.list(
            self.kwargs.create_groups_secrets
        )
        if len(existing_folders):
            existing_folders = [e.replace("/", "") for e in
                                existing_folders['keys']]
        self.logger.debug("Already existing folders: " + str(existing_folders))
        for group in self.conf["groups"]["groups_to_add"]:
            if group not in existing_folders:
                self.logger.info("Creating folder: " + group)
                self.vault_client.write(self.kwargs.create_groups_secrets +
                                        "/" + group + "/description",
                                        {group: "group private secrets space"})
        for group in existing_folders:
            if group not in self.conf["groups"]["groups_to_add"]:
                tree = self.vault_client.get_secrets_tree(
                    self.kwargs.create_groups_secrets + "/" + group)
                self.logger.info(
                    "Deleting folder " + group + " and associated secrets " + str(
                        tree))
                for secret in tree:
                    self.vault_client.delete(secret)

    def ldap_create_users_secrets(self):
        """
        Method running the create-users-secrets function of LDAP module
        Create a secret folder for each LDAP user under specified path
        """
        self.logger.debug("LDAP create-users-secrets starting")
        self.logger.info("Creating users folders under secret path '/%s'" %
                         self.kwargs.create_users_secrets)
        self.logger.debug("Creating users secrets under %s" %
                          self.kwargs.create_users_secrets)
        enabled_users = []
        for user in self.ldap_users:
            groups_of_user = list(
                set(self.conf["groups"]["groups_to_add"]).intersection(
                    self.ldap_users[user]))
            if len(groups_of_user):
                enabled_users.append(user)
        existing_folders = self.vault_client.list(
            self.kwargs.create_users_secrets
        )
        if len(existing_folders):
            existing_folders = [e.replace("/", "") for e in
                                existing_folders['keys']]
        self.logger.debug("Already existing folders: " + str(existing_folders))
        for user in enabled_users:
            if user not in existing_folders:
                self.logger.info("Creating folder: " + user)
                self.vault_client.write(
                    self.kwargs.create_users_secrets + "/" + user + "/description",
                    {user: "user private secrets space"})
        for user in existing_folders:
            if user not in enabled_users:
                tree = self.vault_client.get_secrets_tree(
                    self.kwargs.create_users_secrets + "/" + user)
                self.logger.info(
                    "Deleting folder " + user + " and associated secrets " + str(
                        tree))
                for secret in tree:
                    self.vault_client.delete(secret)

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
            [{"key": "vault_config", "exc": [None, False, '']}]
        )
        if len(missing_args):
            raise ValueError(
                "Following arguments are missing %s\n" % [
                    k['key'].replace("_", "-") for k in missing_args]
            )
        self.policies_folder = os.path.join(
            self.kwargs.vault_config, "policies"
        )
        self.user_policies_folder = os.path.join(self.policies_folder, "user")
        self.kubernetes_policies_folder = os.path.join(self.policies_folder,
                                                       "service", "kubernetes")
        self.group_policies_folder = os.path.join(self.policies_folder, "group")
        self.group_policies_to_create = []
        self.user_policies_to_create = []
        self.kubernetes_policies_to_create = []
        if not self.read_configuration() or not self.read_ldap_configuration():
            return False
        self.vault_client = VaultClient(
            self.base_logger,
            vault_addr=self.kwargs.vault_addr,
            dry=self.kwargs.dry_run,
            skip_tls=self.kwargs.skip_tls
        )
        self.vault_client.authenticate(self.kwargs.vault_token)
        if not self.get_ldap_data():
            return False
        if self.kwargs.list_groups:
            self.ldap_list_groups()
            return True
        if self.kwargs.create_policies:
            self.ldap_create_policies()
            return True
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
        self.vault_client = self.connect_to_vault(
            self.kwargs.vault_addr,
            self.kwargs.vault_token
        )
        if self.kwargs.manage_ldap_groups:
            self.ldap_manage_ldap_groups()
        if self.kwargs.manage_ldap_users:
            self.ldap_manage_ldap_users()
        if self.kwargs.create_groups_secrets:
            self.ldap_create_groups_secrets()
        if self.kwargs.create_users_secrets:
            self.ldap_create_users_secrets()
