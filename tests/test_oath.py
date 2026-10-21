#  vim: set fileencoding=utf-8 :

import pytest

from yubikit.oath import (
    HASH_ALGORITHM,
    OATH_TYPE,
    CredentialData,
    _derive_key,
    _format_cred_id,
    _parse_cred_id,
)


@pytest.mark.parametrize(
    ("raw", "issuer", "name", "period"),
    [
        (b"20/Issuer:name", "Issuer", "name", 20),
        (b"weird/Issuer:name", "weird/Issuer", "name", 30),
        (b"Issuer:name", "Issuer", "name", 30),
        (b"20/name", None, "name", 20),
        (b"name", None, "name", 30),
    ],
)
def test_parse_cred_id(raw, issuer, name, period):
    parsed_issuer, parsed_name, parsed_period = _parse_cred_id(raw, OATH_TYPE.TOTP)
    assert (parsed_issuer, parsed_name, parsed_period) == (issuer, name, period)


@pytest.mark.parametrize(
    ("issuer", "name", "period", "expected"),
    [
        (None, "name", None, b"name"),
        ("Issuer", "name", None, b"Issuer:name"),
        ("Issuer", "name", 20, b"20/Issuer:name"),
        ("Issuer", "name", 30, b"Issuer:name"),
        (None, "name", 20, b"20/name"),
    ],
)
def test_format_cred_id(issuer, name, period, expected):
    kwargs = {}
    if period is not None:
        kwargs["period"] = period
    assert _format_cred_id(issuer, name, OATH_TYPE.TOTP, **kwargs) == expected


@pytest.mark.parametrize(
    ("salt", "password", "expected"),
    [
        (
            b"\0" * 8,
            "foobar",
            b"\xb0}\xa1\xe7\xde\x87\xf8\x9a\x87\xa2\xb5\x98\xea\xa2\x18\x8c",
        ),
        (
            b"12345678",
            "Hallå världen!",
            b"\xda\x81\x8ek,\xf0\xa2\xd0\xbf\x19\xb3\xdd\xd3K\x83\xf5",
        ),
        (
            b"saltsalt",
            "Ťᶒśƫ ᵽĥřӓşḛ",
            b"\xf3\xdf\xa7\x81T\xc8\x102\x99E\xfb\xc4\xb55\xe57",
        ),
    ],
)
def test_derive_key(salt, password, expected):
    assert _derive_key(salt, password) == expected


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        ("otpauth://totp/account?secret=abba", None),
        ("otpauth://totp/account?secret=abba&issuer=Test", "Test"),
        ("otpauth://totp/Test:account?secret=abba", "Test"),
        ("otpauth://totp/TestA:account?secret=abba&issuer=TestB", "TestB"),
    ],
)
def test_parse_uri_issuer(uri, expected):
    assert CredentialData.parse_uri(uri).issuer == expected


def test_parse_uri_full_payload():
    data = CredentialData.parse_uri(
        "otpauth://totp/Issuer:account"
        "?secret=abba&issuer=Issuer"
        "&algorithm=SHA256&digits=7"
        "&period=20&counter=5"
    )
    assert data.secret == b"\0B"
    assert data.issuer == "Issuer"
    assert data.name == "account"
    assert data.oath_type == OATH_TYPE.TOTP
    assert data.hash_algorithm == HASH_ALGORITHM.SHA256
    assert data.digits == 7
    assert data.period == 20
    assert data.counter == 5


def test_oath_keystore_error_handling(monkeypatch):
    from unittest.mock import MagicMock
    from click.testing import CliRunner
    from ykman._cli.oath import oath
    from ykman._cli.util import CliFail, YkmanContextObject
    from ykman.settings import AppData, KeystoreError

    mock_app_data = MagicMock(spec=AppData)
    mock_app_data.ensure_unlocked.side_effect = KeystoreError("Locked")

    mock_session = MagicMock()
    mock_session.locked = True
    mock_session.device_id = "test_device_id"
    mock_session.version = (5, 4, 0)

    mock_info = MagicMock()
    mock_info.fips_capable = ()
    mock_info.fips_approved = ()

    runner = CliRunner()
    mock_dev = MagicMock()
    mock_conn = MagicMock()
    mock_conn.send_and_receive.return_value = (b"\x05\x04\x00", 0x9000)
    mock_dev.open_connection.return_value = mock_conn

    ctx_obj = YkmanContextObject()
    ctx_obj.add_resolver("device", lambda: mock_dev)
    ctx_obj.add_resolver("info", lambda: mock_info)
    ctx_obj.add_resolver("session", lambda: mock_session)
    ctx_obj.add_resolver("oath_keys", lambda: mock_app_data)
    ctx_obj.add_resolver("fips_unready", lambda: False)
    ctx_obj.add_resolver("no_scp", lambda: False)
    ctx_obj.resolve()

    monkeypatch.setattr("ykman._cli.oath.OathSession", lambda conn, scp: mock_session)

    # Test 'access remember' when ensure_unlocked raises KeystoreError
    res = runner.invoke(
        oath,
        ["access", "remember", "-p", "password"],
        obj=ctx_obj,
    )
    assert res.exit_code != 0
    assert isinstance(res.exception, CliFail)
    assert "Failed to remember password, the keyring is locked or unavailable." in str(res.exception)


def test_import_pskc_preshared_key_prompt_hidden_input(monkeypatch, tmp_path):
    from unittest.mock import MagicMock
    from click.testing import CliRunner
    from ykman._cli.__main__ import cli

    pskc_file = tmp_path / "encrypted.pskc"
    pskc_file.write_bytes(b"dummy_pskc_content")

    mock_key = MagicMock()
    mock_key.algorithm = "urn:ietf:params:xml:ns:keyprov:pskc:totp"
    mock_key.secret = b"secretkey"
    mock_key.id = "test_key"
    mock_key.friendly_name = None
    mock_key.issuer = None
    mock_key.key_userid = None
    mock_key.time_interval = 30
    mock_key.response_length = 6
    mock_key.algorithm_suite = "sha1"
    mock_key.counter = None

    mock_pskc = MagicMock()
    mock_pskc.encryption.is_encrypted = True
    mock_pskc.encryption.derivation.algorithm = None
    mock_pskc.keys = [mock_key]

    mock_click_prompt = MagicMock(return_value="00112233445566778899aabbccddeeff")

    mock_session = MagicMock()
    mock_session.locked = False
    mock_session.device_id = "test_device_id"
    mock_session.version = (5, 4, 0)
    mock_session.list_credentials.return_value = []

    mock_info = MagicMock()
    mock_info.fips_capable = ()
    mock_info.fips_approved = ()

    mock_dev = MagicMock()
    mock_conn = MagicMock()
    mock_dev.open_connection.return_value = mock_conn

    monkeypatch.setattr("ykman._cli.oath.PSKC", lambda f: mock_pskc)
    monkeypatch.setattr("ykman._cli.oath.click_prompt", mock_click_prompt)
    monkeypatch.setattr("ykman._cli.__main__.require_device", lambda conn, serial: (mock_dev, mock_info))
    monkeypatch.setattr("ykman._cli.oath.OathSession", lambda conn, scp: mock_session)

    runner = CliRunner()
    res = runner.invoke(
        cli,
        ["oath", "accounts", "import", str(pskc_file)],
        input="y\n",
    )

    assert res.exit_code == 0
    mock_click_prompt.assert_called_once_with(
        "Enter pre-shared key (32 char hex) to decrypt PSKC file",
        hide_input=True,
    )


def test_add_account_pskc_preshared_key_prompt_hidden_input(monkeypatch, tmp_path):
    from unittest.mock import MagicMock
    from click.testing import CliRunner
    from ykman._cli.__main__ import cli

    pskc_file = tmp_path / "export.pskc"
    mock_click_prompt = MagicMock(return_value="00112233445566778899aabbccddeeff")

    mock_session = MagicMock()
    mock_session.locked = False
    mock_session.device_id = "test_device_id"
    mock_session.version = (5, 4, 0)
    mock_session.list_credentials.return_value = []

    mock_info = MagicMock()
    mock_info.serial = 123456
    mock_info.fips_capable = ()
    mock_info.fips_approved = ()

    mock_dev = MagicMock()
    mock_conn = MagicMock()
    mock_dev.open_connection.return_value = mock_conn

    monkeypatch.setattr("ykman._cli.oath.click_prompt", mock_click_prompt)
    monkeypatch.setattr("ykman._cli.__main__.require_device", lambda conn, serial: (mock_dev, mock_info))
    monkeypatch.setattr("ykman._cli.oath.OathSession", lambda conn, scp: mock_session)

    runner = CliRunner()
    res = runner.invoke(
        cli,
        [
            "oath",
            "accounts",
            "add",
            "test_user",
            "GEZDGNBVGY3TQOJQ",
            "-O",
            str(pskc_file),
            "--pskc-key",
            "-",
            "-f",
        ],
    )

    assert res.exit_code == 0
    mock_click_prompt.assert_called_once_with(
        "Enter pre-shared key (hex) to encrypt PSKC file",
        hide_input=True,
        confirmation_prompt=True,
    )
