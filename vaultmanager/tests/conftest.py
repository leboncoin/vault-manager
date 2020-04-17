import pytest
import os
import hvac
import subprocess
import shutil


@pytest.fixture(autouse=True)
def env_setup(monkeypatch, tmp_path):
    monkeypatch.setenv('VAULT_TOKEN', 'root_token')
    monkeypatch.setenv('VAULT_ADDR', 'http://127.0.0.1:' + os.getenv("VAULT_8200_TCP_PORT"))
    monkeypatch.setenv('VAULT_CONFIG', os.path.join(tmp_path, "vault_config"))


@pytest.fixture
def vault_client():
    client = hvac.Client(url=os.getenv("VAULT_ADDR"), token=os.getenv("VAULT_TOKEN"))
    assert client.is_authenticated()
    return client


@pytest.fixture(autouse=True)
def mock_vault_config(tmp_path):
    shutil.copytree(
        os.path.join("tests", "vault_config"),
        os.path.join(tmp_path, "vault_config")
    )
