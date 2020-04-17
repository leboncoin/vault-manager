import subprocess
import os
import glob

DEFAULT_POLICIES = ["default", "root"]


def cli(args):
    proc = subprocess.run(
        ["vault-manager"] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return proc.stdout, proc.stderr, proc.returncode


def test_policies_push_creation(vault_client):
    """
    Test the push of local policies
    """
    distant_policies = vault_client.list_policies()
    # There should be only the 2 default policies 'default' and 'root'
    assert len(distant_policies) == len(DEFAULT_POLICIES)
    assert all(pol in distant_policies for pol in DEFAULT_POLICIES)
    # We push the local policies
    out, err, rc = cli(["policies", "--push"])
    distant_policies = vault_client.list_policies()
    target_policies = [
        "group_group1_policy",
        "group_group2_policy",
        "service_app1_policy",
        "service_app2_policy",
        "user_user1_policy",
        "user_user2_policy"
    ] + DEFAULT_POLICIES
    distant_policies = vault_client.list_policies()
    # There should now be 8 policies
    assert len(target_policies) == len(target_policies)
    assert all(pol in distant_policies for pol in target_policies)


def test_policies_push_deletion(vault_client):
    """
    The the deletion of distant Vault policies
    """
    # We remove half of local policies to check if deletion is working properly
    for pol in glob.glob(os.path.join(os.getenv("VAULT_CONFIG"), "policies", "**/*2.hcl")):
        os.remove(pol)
    # We push theses policies
    # We expect half of distant policies to be deleted
    target_policies = [
        "group_group2_policy",
        "service_app2_policy",
        "user_user2_policy"
    ] + DEFAULT_POLICIES
    distant_policies = vault_client.list_policies()
    assert len(target_policies) == len(target_policies)
    assert all(pol in distant_policies for pol in target_policies)
