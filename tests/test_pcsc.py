from unittest.mock import MagicMock, patch

import pytest
from ykman.pcsc import kill_scdaemon, kill_yubikey_agent


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_kill_scdaemon_non_windows_success(platform):
    with (
        patch("sys.platform", platform),
        patch("subprocess.call", return_value=0) as mock_call,
        patch("ykman.pcsc.sleep") as mock_sleep,
    ):
        assert kill_scdaemon() is True
        mock_call.assert_called_once_with(["pkill", "-9", "scdaemon"])
        mock_sleep.assert_called_once_with(0.1)


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_kill_scdaemon_non_windows_failure(platform):
    with (
        patch("sys.platform", platform),
        patch("subprocess.call", return_value=1) as mock_call,
        patch("ykman.pcsc.sleep") as mock_sleep,
    ):
        assert kill_scdaemon() is False
        mock_call.assert_called_once_with(["pkill", "-9", "scdaemon"])
        mock_sleep.assert_not_called()


def test_kill_scdaemon_windows_success():
    win32api_mock = MagicMock()
    win32com_mock = MagicMock()

    win32api_mock.OpenProcess.return_value = "fake_handle"

    p1 = MagicMock()
    p1.Properties_ = lambda prop: MagicMock(
        Value="scdaemon.exe" if prop == "Name" else 1234
    )

    p2 = MagicMock()
    p2.Properties_ = lambda prop: MagicMock(
        Value="explorer.exe" if prop == "Name" else 5678
    )

    wmi = MagicMock()
    wmi.InstancesOf.return_value = [p1, p2]
    win32com_mock.client.GetObject.return_value = wmi

    modules = {
        "win32api": win32api_mock,
        "win32com": win32com_mock,
        "win32com.client": win32com_mock.client,
    }

    with (
        patch("sys.platform", "win32"),
        patch.dict("sys.modules", modules),
        patch("ykman.pcsc.sleep") as mock_sleep,
    ):
        assert kill_scdaemon() is True

        win32com_mock.client.GetObject.assert_called_once_with("winmgmts:")
        wmi.InstancesOf.assert_called_once_with("Win32_Process")
        win32api_mock.OpenProcess.assert_called_once_with(1, False, 1234)
        win32api_mock.TerminateProcess.assert_called_once_with("fake_handle", -1)
        win32api_mock.CloseHandle.assert_called_once_with("fake_handle")
        mock_sleep.assert_called_once_with(0.1)


def test_kill_scdaemon_windows_process_not_found():
    win32api_mock = MagicMock()
    win32com_mock = MagicMock()

    p1 = MagicMock()
    p1.Properties_ = lambda prop: MagicMock(
        Value="explorer.exe" if prop == "Name" else 5678
    )

    wmi = MagicMock()
    wmi.InstancesOf.return_value = [p1]
    win32com_mock.client.GetObject.return_value = wmi

    modules = {
        "win32api": win32api_mock,
        "win32com": win32com_mock,
        "win32com.client": win32com_mock.client,
    }

    with (
        patch("sys.platform", "win32"),
        patch.dict("sys.modules", modules),
        patch("ykman.pcsc.sleep") as mock_sleep,
    ):
        assert kill_scdaemon() is False

        win32api_mock.OpenProcess.assert_not_called()
        win32api_mock.TerminateProcess.assert_not_called()
        win32api_mock.CloseHandle.assert_not_called()
        mock_sleep.assert_not_called()


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_kill_yubikey_agent_non_windows_success(platform):
    with (
        patch("sys.platform", platform),
        patch("subprocess.call", return_value=0) as mock_call,
        patch("ykman.pcsc.sleep") as mock_sleep,
    ):
        assert kill_yubikey_agent() is True
        mock_call.assert_called_once_with(["pkill", "-HUP", "yubikey-agent"])
        mock_sleep.assert_called_once_with(0.1)


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_kill_yubikey_agent_non_windows_failure(platform):
    with (
        patch("sys.platform", platform),
        patch("subprocess.call", return_value=1) as mock_call,
        patch("ykman.pcsc.sleep") as mock_sleep,
    ):
        assert kill_yubikey_agent() is False
        mock_call.assert_called_once_with(["pkill", "-HUP", "yubikey-agent"])
        mock_sleep.assert_not_called()


def test_kill_yubikey_agent_windows():
    with (
        patch("sys.platform", "win32"),
        patch("subprocess.call") as mock_call,
        patch("ykman.pcsc.sleep") as mock_sleep,
    ):
        assert kill_yubikey_agent() is False
        mock_call.assert_not_called()
        mock_sleep.assert_not_called()
