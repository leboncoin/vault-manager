import subprocess
import os


def cli(args):
    proc = subprocess.run(
        ["vault-manager"] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return proc.stdout, proc.stderr, proc.returncode


def test_audit_creation(vault_client):
    audit_devices = vault_client.list_audit_backends()
    assert len(audit_devices["data"]) == 0
    out, err, rc = cli(["audit", "--push"])
    assert rc == 0
    audit_devices = vault_client.list_audit_backends()
    assert len(audit_devices["data"]) == 1
    assert "file_log/" in audit_devices["data"]
    file_audit = audit_devices["data"]["file_log/"]
    assert file_audit["type"] == "file"
    assert file_audit["description"] == "File audit log"
    assert file_audit["options"]["file_path"] == "/tmp/vault_audit.log"


def test_audit_no_deletion(vault_client, tmp_path):
    audit_devices = vault_client.list_audit_backends()
    assert len(audit_devices["data"]) == 1
    with open(os.path.join(os.getenv("VAULT_CONFIG"), "audit-devices.yml"), 'w') as fd:
        fd.write("---\naudit-devices: []\n")
    out, err, rc = cli(["audit", "--push"])
    assert rc == 0
    audit_devices = vault_client.list_audit_backends()
    assert len(audit_devices["data"]) == 1


def test_audit_deletion(vault_client, tmp_path):
    audit_devices = vault_client.list_audit_backends()
    assert len(audit_devices["data"]) == 1
    with open(os.path.join(os.getenv("VAULT_CONFIG"), "audit-devices.yml"), 'w') as fd:
        fd.write("---\naudit-devices: []\naudit-devices-deletion: true\n")
    out, err, rc = cli(["audit", "--push"])
    assert rc == 0
    audit_devices = vault_client.list_audit_backends()
    assert len(audit_devices["data"]) == 0
