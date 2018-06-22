import string
import ldap
import logging


class LDAPReader:
    logger = None
    ldap_connector = None
    ldap_server = None
    ldap_username = None
    ldap_password = None
    group_dn = None
    user_dn = None
    ldap_connector = None

    def __init__(self, base_logger, server, user, password, group_dn, user_dn):
        self.logger = logging.getLogger(base_logger + "." +
                                        self.__class__.__name__)
        self.logger.debug("Initializing LDAP connector")
        self.ldap_server = server
        self.ldap_username = user
        self.ldap_password = password
        self.group_dn = group_dn
        self.user_dn = user_dn
        self.ldap_connector = ldap.initialize(self.ldap_server)
        self.ldap_connector.protocol_version = 3
        self.ldap_connector.set_option(ldap.OPT_REFERRALS, 0)

    def connect_to_ldap(self):
        self.logger.debug("Connecting to LDAP server")
        try:
            resp_type, resp_data, resp_msgid, resp_ctrls = self.ldap_connector.simple_bind_s(self.ldap_username, self.ldap_password)
        except ldap.INVALID_CREDENTIALS as e:
            self.logger.critical("Your username or password is incorrect: " + str(e))
            return False
        except ldap.SERVER_DOWN as e:
            self.logger.critical("The server appears to be down: " + str(e))
            return False
        except Exception as e:
            self.logger.critical(str(e))
            return False
        self.logger.debug("Connection successful")
        return True

    def get_all_groups(self):
        self.logger.debug("Fetching all groups")
        criteria = "(&(objectClass=group))"
        attributes = ['sAMAccountName']
        try:
            result = self.ldap_connector.search_s(self.group_dn, ldap.SCOPE_SUBTREE,
                                                  filterstr=criteria, attrlist=attributes)
            groups = [entry['sAMAccountName'][0].decode() for dn, entry in result if isinstance(entry, dict)]
        except Exception as e:
            self.logger.error("Impossible to fetch groups :" + str(e))
            groups = None
        if groups:
            self.logger.debug(groups)
        return groups

    def get_all_users(self, groups):
        self.logger.debug("Fetching all users")
        users = {}
        for letter in string.ascii_lowercase:
            self.logger.debug("Checking letter " + letter)
            criteria = "(&(objectClass=user)(objectClass=person)(sAMAccountName=" + letter + "*))"
            attributes = ['sAMAccountName', 'memberOf']
            result = self.ldap_connector.search_s(self.user_dn, ldap.SCOPE_SUBTREE,
                                                  filterstr=criteria, attrlist=attributes)
            users_raw = [entry for dn, entry in result if isinstance(entry, dict)]
            for user_raw in users_raw:
                if user_raw['sAMAccountName'][0].decode() in users or 'memberOf' not in user_raw:
                    self.logger.error("Duplicated user " + user_raw['sAMAccountName'][0].decode())
                    continue
                users[user_raw['sAMAccountName'][0].decode()] = []
                for group_path in [u.decode() for u in user_raw['memberOf']]:
                    users[user_raw['sAMAccountName'][0].decode()] += [g for g in groups if g in group_path]
                if not len(users[user_raw['sAMAccountName'][0].decode()]):
                    users.pop(user_raw['sAMAccountName'][0].decode())
                    self.logger.debug("No groups for " + user_raw['sAMAccountName'][0].decode() + ". Deleting user")
        self.logger.debug("Users found: ")
        for user in users:
            self.logger.debug(user + " " + str(users[user]))
        return users

    def disconnect_from_ldap(self):
        self.logger.debug("Disconnection successful")
        self.ldap_connector.unbind_s()
