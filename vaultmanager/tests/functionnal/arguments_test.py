import os
import subprocess


def cli(args, env=None):
    if env:
        proc = subprocess.run(
            ["vault-manager"] + args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env
        )
    else:
        proc = subprocess.run(
            ["vault-manager"] + args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
    return proc.stdout, proc.stderr, proc.returncode


def delete_keys_from_dict(source_dict, keys_to_delete):
    for key in keys_to_delete:
        if key in source_dict:
            del source_dict[key]
    return source_dict


def test_env_vars_params_absent():
    modified_env = delete_keys_from_dict(
        os.environ.copy(), ["VAULT_ADDR", "VAULT_TOKEN", "VAULT_CONFIG"]
    )
    out, err, rc = cli(
        ["policies", "--pull"],
        env=modified_env
    )
    assert rc == 1


def test_env_vars_params_present():
    out, err, rc = cli(
        ["policies", "--pull"]
    )
    assert rc == 0

# def test_command_line_params_present(tmp_path):
#     modified_env = delete_keys_from_dict(
#         os.environ.copy(), ["VAULT_ADDR", "VAULT_TOKEN", "VAULT_CONFIG"]
#     )
#     out, err, rc = cli(
#         ["--vault-addr", os.getenv("VAULT_ADDR"),
#         "--vault_config", os.getenv("VAULT_CONFIG")),
#         "--vault_token"
#         "policies", "--pull"],
#         env=modified_env
#     )
