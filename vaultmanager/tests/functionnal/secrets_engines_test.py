import subprocess
import os

DEFAULT_SECRETS_ENGINES = ["cubbyhole/", "identity/", "secret/", "sys/"]


def cli(args):
    proc = subprocess.run(
        ["vault-manager"] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return proc.stdout, proc.stderr, proc.returncode


def test_secrets_engines_creation(vault_client):
    """
    Test the creation of secrets engines
    """
    secrets_engines = vault_client.list_secret_backends()["data"]
    # There should be only default secrets engines
    assert len(secrets_engines) == len(DEFAULT_SECRETS_ENGINES)
    assert all(pol in secrets_engines for pol in DEFAULT_SECRETS_ENGINES)
    # The push local secrets engines
    out, err, rc = cli(["secret", "--push"])
    secrets_engines = vault_client.list_secret_backends()["data"]
    target_secrets_engines = [
        "apps/",
        "resources/",
        "services/",
    ] + DEFAULT_SECRETS_ENGINES
    # New secrets engines should be added
    assert len(secrets_engines) == len(target_secrets_engines)
    assert all(pol in secrets_engines for pol in target_secrets_engines)


def test_secrets_engines_tuning(vault_client):
    """
    Test of secrets engines tuning
    """
    secrets_engines = vault_client.list_secret_backends()["data"]
    assert "config" in secrets_engines["apps/"]
    assert "config" in secrets_engines["resources/"]
    assert "config" in secrets_engines["services/"]
    assert secrets_engines["apps/"]["config"]["default_lease_ttl"] == 30
    assert secrets_engines["apps/"]["config"]["max_lease_ttl"] == 32
    assert secrets_engines["resources/"]["config"]["default_lease_ttl"] == 0
    assert secrets_engines["resources/"]["config"]["max_lease_ttl"] == 0
    assert secrets_engines["services/"]["config"]["default_lease_ttl"] == 60
    assert secrets_engines["services/"]["config"]["max_lease_ttl"] == 120


def test_secrets_engines_no_deletion(vault_client):
    """
    Test the deletion of secrets engines
    """
    with open(os.path.join(os.getenv("VAULT_CONFIG"), "secrets-engines.yml"), 'w') as fd:
        fd.write("---\nsecrets-engines: []\n")
    out, err, rc = cli(["-vvv", "secret", "--push"])
    # print(out.decode())
    secrets_engines = vault_client.list_secret_backends()["data"]
    target_secrets_engines = [
        "apps/",
        "resources/",
        "services/",
    ] + DEFAULT_SECRETS_ENGINES
    assert len(secrets_engines) == len(target_secrets_engines)
    assert all(pol in secrets_engines for pol in target_secrets_engines)


def test_secrets_engines_deletion(vault_client):
    """
    Test the deletion of secrets engines
    """
    with open(os.path.join(os.getenv("VAULT_CONFIG"), "secrets-engines.yml"), 'w') as fd:
        fd.write("---\nsecrets-engines: []\nsecret-engines-deletion: true\n")
    out, err, rc = cli(["-vvv", "secret", "--push"])
    secrets_engines = vault_client.list_secret_backends()["data"]
    target_secrets_engines = DEFAULT_SECRETS_ENGINES
    target_secrets_engines.remove("secret/")
    assert len(secrets_engines) == len(target_secrets_engines)
    assert all(pol in secrets_engines for pol in target_secrets_engines)
