import subprocess
import yaml
import os


def cli(args):
    proc = subprocess.run(
        ["vault-manager"] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    return proc.stdout, proc.stderr, proc.returncode


def test_auth_creation(vault_client):
    """
    Test Token auth creation
    """
    auth_methods = vault_client.list_auth_backends()["data"]
    assert len(auth_methods) == 1
    assert "token/" in auth_methods
    out, err, rc = cli(["auth", "--push"])
    assert rc == 0
    auth_methods = vault_client.list_auth_backends()["data"]
    target_auth = [
        "token/",
        "approle/",
        "approle2/"
    ]
    assert len(auth_methods) == len(target_auth)
    assert all(auth in auth_methods for auth in target_auth)


def test_auth_tuning(vault_client):
    """
    Test auth tuning
    """
    auth_methods = vault_client.list_auth_backends()["data"]
    assert "config" in auth_methods["approle/"]
    assert "config" in auth_methods["token/"]
    assert "config" in auth_methods["approle2/"]
    assert auth_methods["approle/"]["config"]["default_lease_ttl"] == 43200
    assert auth_methods["approle/"]["config"]["max_lease_ttl"] == 0
    assert auth_methods["token/"]["config"]["default_lease_ttl"] == 0
    assert auth_methods["token/"]["config"]["max_lease_ttl"] == 0
    assert auth_methods["approle2/"]["config"]["default_lease_ttl"] == 0
    assert auth_methods["approle2/"]["config"]["max_lease_ttl"] == 86400


def test_auth_no_deletion(vault_client):
    """
    Test deletion of auth methods
    """
    with open(os.path.join(os.getenv("VAULT_CONFIG"), "auth-methods.yml"), 'r') as fd:
        local_auth = yaml.safe_load(fd)["auth-methods"]
    new_auth = [a for a in local_auth if a["path"] != "approle2"]
    with open(os.path.join(os.getenv("VAULT_CONFIG"), "auth-methods.yml"), 'w') as fd:
        yaml.dump({"auth-methods": new_auth}, fd)
    out, err, rc = cli(["auth", "--push"])
    assert rc == 0
    auth_methods = vault_client.list_auth_backends()["data"]
    target_auth = ["token/", "approle/", "approle2/"]
    assert len(auth_methods) == len(target_auth)
    assert all(auth in auth_methods for auth in target_auth)


def test_auth_deletion(vault_client):
    """
    Test deletion of auth methods
    """
    with open(os.path.join(os.getenv("VAULT_CONFIG"), "auth-methods.yml"), 'r') as fd:
        local_auth = yaml.safe_load(fd)["auth-methods"]
    new_auth = [a for a in local_auth if a["path"] != "approle2"]
    with open(os.path.join(os.getenv("VAULT_CONFIG"), "auth-methods.yml"), 'w') as fd:
        yaml.dump(
            {
                "auth-methods": new_auth,
                "auth-methods-deletion": True
            }, fd
        )
    out, err, rc = cli(["auth", "--push"])
    assert rc == 0
    auth_methods = vault_client.list_auth_backends()["data"]
    target_auth = ["token/", "approle/"]
    assert len(auth_methods) == len(target_auth)
    assert all(auth in auth_methods for auth in target_auth)


def test_auth_approle_role_initial(vault_client):
    roles = vault_client.list_roles("approle/")["data"]["keys"]
    assert len(roles) == 1
    assert "app2" in roles
    role = vault_client.get_role("app2", "approle/")["data"]
    assert len(role["token_policies"]) == 1
    assert "service_app2_policy" in role["token_policies"]


def test_auth_approle_role_creation(vault_client):
    with open(os.path.join(os.getenv("VAULT_CONFIG"), "auth-methods.yml"), 'r') as fd:
        local_auth = yaml.safe_load(fd)["auth-methods"]
    for l_a in local_auth:
        if l_a["path"] == "approle":
            l_a["auth_config"]["new_role"] = {
                "role_name": "new_role",
                "token_policies": ["service_new_role_policy", "service_app2_policy"]
            }
    with open(os.path.join(os.getenv("VAULT_CONFIG"), "auth-methods.yml"), 'w') as fd:
        yaml.dump({"auth-methods": local_auth}, fd)
    out, err, rc = cli(["auth", "--push"])
    assert rc == 0
    roles = vault_client.list_roles("approle/")["data"]["keys"]
    assert len(roles) == 2
    assert "new_role" in roles
    assert "app2" in roles
    role = vault_client.get_role("new_role", "approle/")["data"]
    assert len(role["token_policies"]) == 2
    assert "service_new_role_policy" in role["token_policies"]
    assert "service_app2_policy" in role["token_policies"]


def test_auth_approle_role_deletion(vault_client):
    with open(os.path.join(os.getenv("VAULT_CONFIG"), "auth-methods.yml"), 'r') as fd:
        local_auth = yaml.safe_load(fd)["auth-methods"]
    out, err, rc = cli(["auth", "--push"])
    assert rc == 0
    roles = vault_client.list_roles("approle/")["data"]["keys"]
    assert len(roles) == 1
    assert "app2" in roles
    role = vault_client.get_role("app2", "approle/")["data"]
    assert len(role["token_policies"]) == 1
    assert "service_app2_policy" in role["token_policies"]
