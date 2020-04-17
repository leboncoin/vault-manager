import os
import ldap
import ldif
import time
import subprocess
import ldap.modlist as modlist

time.sleep(4)
LDAP = ldap.initialize("ldap://localhost:%s/" % (os.getenv("OSIXIA_OPENLDAP_389_TCP_PORT")))
LDAP.simple_bind_s("cn=admin,dc=company,dc=com", "admin")


def cli(args):
    proc = subprocess.run(
        ["vault-manager"] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    return proc.stdout, proc.stderr, proc.returncode


def test_init_ldap_server():
    """
    Create some resources in the LDAP instance
    """
    with open(os.path.join(os.getenv("VAULT_CONFIG"), "ldap-config.ldif"), 'rb') as fd:
        ldif_parser = ldif.LDIFRecordList(fd)
        ldif_parser.parse()
        for dn, entry in ldif_parser.all_records:
            add_modlist = modlist.addModlist(entry)
            LDAP.add_s(dn, add_modlist)

# def test_list_ldap_groups():
#     """
#     Check the --list-groups command
#     """
#     with fileinput.FileInput(os.path.join(os.getenv("VAULT_CONFIG"), "ldap.yml"), inplace=True) as file:
#         for line in file:
#             print(line.replace("{{PORT}}", str(os.getenv("OSIXIA_OPENLDAP_389_TCP_PORT"))), end='')
#     out, err, rc = cli(["-vvvv", "ldap", "--list-groups"])
#     print(err)
#     for e in out.decode().split("\n"):
#         print(e)
#     print(rc)
