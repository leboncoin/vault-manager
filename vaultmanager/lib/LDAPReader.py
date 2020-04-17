import re
import string
import ldap
import logging


class LDAPReader:
    """
    Allows to reach and read LDAP
    """
    logger = None
    ldap_connector = None
    ldap_server = None
    ldap_username = None
    ldap_password = None
    group_dn = None
    user_dn = None
    ldap_connector = None

    def __init__(self, base_logger, server, user, password, kubernetes_group_dn,
                 group_dn, user_dn):
        """
        Instanciate class

        :param base_logger: parent logger
        :type base_logger: str
        :param server: LDAP address
        :type server: str
        :param user: LDAP username
        :type user: str
        :param password: LDAP password
        :type password: str
        :param group_dn: Group DN
        :type group_dn: str
        :param user_dn: User DN
        :type user_dn: str
        """
        self.logger = logging.getLogger(base_logger + "." +
                                        self.__class__.__name__)
        self.logger.debug("Initializing LDAP connector")
        self.ldap_server = server
        self.ldap_username = user
        self.ldap_password = password
        self.group_dn = group_dn
        self.kubernetes_group_dn = kubernetes_group_dn
        self.user_dn = user_dn
        self.logger.debug("LDAP parameters:")
        self.logger.debug("\tserver: " + self.ldap_server)
        self.logger.debug("\tusername: " + self.ldap_username)
        self.logger.debug("\tgroup_dn: " + self.group_dn)
        self.logger.debug("\tkubernetes_group_dn: " + self.kubernetes_group_dn)
        self.logger.debug("\tuser_dn: " + self.user_dn)
        self.ldap_connector = ldap.initialize(self.ldap_server)
        self.ldap_connector.protocol_version = 3
        self.ldap_connector.set_option(ldap.OPT_REFERRALS, 0)

    def connect_to_ldap(self):
        """
        Create the connection to the LDAP server
        """
        self.logger.debug("Connecting to LDAP server")
        try:
            self.ldap_connector.simple_bind_s(self.ldap_username,
                                              self.ldap_password)
        except ldap.INVALID_CREDENTIALS as e:
            self.logger.critical(
                "LDAP: Your username or password is incorrect: " + str(e)
            )
            return False
        except ldap.SERVER_DOWN as e:
            self.logger.critical(
                "LDAP: The server appears to be down: " + str(e))
            return False
        except Exception as e:
            self.logger.critical(str(e))
            return False
        self.logger.debug("Connection successful")
        return True

    def get_all_groups(self):
        """
        Fetch the list of all groups on the LDAP server
        Only groups directly affiliated to a user will be fetched

        :return: list(str)
        """
        self.logger.debug("Fetching all groups")
        criteria = "(&(objectClass=group))"
        group_attr = "sAMAccountName"
        attributes = [group_attr]
        try:
            result = self.ldap_connector.search_s(self.group_dn,
                                                  ldap.SCOPE_SUBTREE,
                                                  filterstr=criteria,
                                                  attrlist=attributes)
            groups = [entry[group_attr][0].decode() for dn, entry in result if
                      isinstance(entry, dict)]
        except Exception as e:
            self.logger.debug("Impossible to fetch groups :" + str(e))
            groups = None
        if groups:
            self.logger.debug(groups)
        return groups

    def get_kubernetes_groups(self):
        """
        Fetch the list of all groups on the LDAP server
        Only groups directly affiliated to a user will be fetched

        :return: list(str)
        """
        self.logger.debug("Fetching all groups")
        criteria = "(&(objectClass=group))"
        group_attr = "sAMAccountName"
        attributes = [group_attr]
        try:
            result = self.ldap_connector.search_s(self.kubernetes_group_dn,
                                                  ldap.SCOPE_SUBTREE,
                                                  filterstr=criteria,
                                                  attrlist=attributes)
            groups = [entry[group_attr][0].decode() for dn, entry in result if
                      isinstance(entry, dict)]
            groups = [g for g in groups if re.match("(team|guild)-", g)]
        except Exception as e:
            self.logger.debug("Impossible to fetch groups :" + str(e))
            groups = None
        if groups:
            self.logger.debug(groups)
        return groups

    def get_all_users(self, groups):
        """
        Fetch all users in a list of groups

        :param groups: List of groups to look for users
        :type groups: list
        :return: list
        """
        self.logger.debug("Fetching all users")
        users = {}
        user_key = "sAMAccountName"
        for letter in string.ascii_lowercase:
            self.logger.debug("Checking letter " + letter)
            criteria = "(&(objectClass=user)(objectClass=person)(" + user_key + "=" + letter + "*))"  # noqa
            attributes = [user_key, 'memberOf']
            result = self.ldap_connector.search_s(self.user_dn,
                                                  ldap.SCOPE_SUBTREE,
                                                  filterstr=criteria,
                                                  attrlist=attributes)
            users_raw = [entry for dn, entry in result if
                         isinstance(entry, dict)]
            for user_raw in [u for u in users_raw if user_key in u]:
                if user_raw[user_key][0].decode() in users or 'memberOf' not in user_raw:  # noqa
                    self.logger.debug(
                        "Duplicated user " + user_raw[user_key][0].decode())
                    continue
                users[user_raw[user_key][0].decode()] = []
                for group_path in [u.decode() for u in user_raw['memberOf']]:
                    users[user_raw[user_key][0].decode()] += [g for g in groups
                                                              if
                                                              g in group_path]
                if not len(users[user_raw[user_key][0].decode()]):
                    users.pop(user_raw[user_key][0].decode())
                    self.logger.debug("No groups for " + user_raw[user_key][
                        0].decode() + ". Deleting user")
        self.logger.debug("Users found: ")
        for user in users:
            self.logger.debug(user + " " + str(users[user]))
        return users

    def disconnect_from_ldap(self):
        """
        Disconnect from LDAP server
        """
        self.logger.debug("Disconnection successful")
        self.ldap_connector.unbind_s()
