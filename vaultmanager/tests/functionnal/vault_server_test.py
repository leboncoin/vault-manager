def test_vault_dev_server(vault_client):
    assert vault_client.is_authenticated()
