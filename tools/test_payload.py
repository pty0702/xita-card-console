#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""隔离验证授权与安全载荷；先运行 tools/build_test_payload.ps1，不使用真实卡库或网络。"""
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import types
from contextlib import ExitStack, redirect_stdout
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
config = types.ModuleType("common.config")
config.KEY = b"isolated-test-key"
config.PORT = 9000
config.PUBLIC_KEY_HEX = ""
config.CARD_LEN = 32
config.USE_TLS = True
config.CERT_SHA256 = ""
config.TS_WINDOW = 60
sys.modules["common.config"] = config
from client import shell
from common import crypto


def main():
    stub = ROOT / "artifacts" / "test-payload" / "XitaTestStub.exe"
    assert stub.is_file(), "先运行 pwsh -NoProfile -File tools/build_test_payload.ps1"
    artifacts = ROOT / "artifacts" / "test-payload"
    card, machine = "TEST" + "0" * 28, "TEST-MACHINE"
    secret, public = crypto.ed25519.gen_keypair()
    def signed_reply(kind="永久卡", expiry="永久"):
        msg = "|".join((card, machine, expiry, kind)).encode("gbk")
        return "验证成功|到期时间:%s|授权类型:%s|授权=%s" % (
            expiry, kind, crypto.ed25519.sign(secret, msg).hex())

    def signed_cache(kind, expiry):
        msg = "|".join((card, machine, expiry, kind)).encode("gbk")
        return b"SIG2" + len(msg).to_bytes(4, "little") + msg + crypto.ed25519.sign(secret, msg)

    reply = signed_reply()
    real_popen = subprocess.Popen
    with tempfile.TemporaryDirectory(prefix="check-", dir=artifacts) as work, ExitStack() as stack:
        work = Path(work)
        for name, value in {"APP_DIR": str(work), "INI": str(work / "用户配置.ini"),
                            "LIC": str(work / "license.dat"), "PAYLOAD": str(work / "payload.bin")}.items():
            stack.enter_context(patch.object(shell, name, value))
        stack.enter_context(patch.object(shell.config, "KEY", b"isolated-test-key"))
        stack.enter_context(patch.object(shell.config, "PUBLIC_KEY_HEX", public.hex()))
        stack.enter_context(patch.object(shell, "machine_code", return_value=machine))
        stack.enter_context(patch.object(shell.runtime, "app_dir", return_value=str(work)))
        stack.enter_context(patch.object(shell.tempfile, "gettempdir", return_value=str(work)))
        stack.enter_context(patch.object(shell.socket, "create_connection", side_effect=AssertionError("禁止测试联网")))
        client = stack.enter_context(patch.object(shell.Client, "call", return_value=reply))
        stack.enter_context(redirect_stdout(io.StringIO()))
        body = stub.read_bytes()
        Path(shell.PAYLOAD).write_bytes(b"FJPK" + crypto.seal(shell.config.KEY, body))

        with patch.object(shell.subprocess, "Popen", side_effect=AssertionError("只验证模式禁止启动")):
            assert shell.run_cli(card, offline=True, verify_only=True) != 0
            assert shell.run_cli(card, offline=True) != 0
            assert shell.run_cli(card, verify_only=True) == 0
            assert client.call_count == 1
            assert Path(shell.LIC).read_bytes().startswith(b"SIG2")
            assert shell.load_license(machine) == (card, "永久")
            assert shell.read_ini()["卡号"] == card
            assert shell.run_cli(card, offline=True, verify_only=True) == 0
            assert client.call_count == 1
            raw = Path(shell.LIC).read_bytes()
            Path(shell.LIC).write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
            assert shell.run_cli(card, offline=True, verify_only=True) != 0
            Path(shell.LIC).write_bytes(raw)
            assert shell.load_license("OTHER-MACHINE") is None

            # 旧格式即使签名正确、攻击者已知对称 KEY，也不能再离线使用。
            old_msg = (card + "|" + machine + "|永久").encode("gbk")
            old_header = len(old_msg).to_bytes(4, "little") + old_msg
            for legacy in (b"SIG1" + old_header + crypto.ed25519.sign(secret, old_msg),
                           b"HMA1" + old_header + crypto.sign(config.KEY, old_msg),
                           old_header + crypto.sign(config.KEY, old_msg)):
                Path(shell.LIC).write_bytes(legacy)
                assert shell.load_license(machine) is None
            for kind, expiry in (("点数卡", "永久"), ("未知卡", "永久"),
                                 ("时间卡", "永久"), ("试用", ""),
                                 ("时间卡", "2099-02-31 00:00:00"),
                                 ("试用", "2000-01-01 00:00:00"),
                                 ("永久卡", "2099-01-01 00:00:00")):
                Path(shell.LIC).write_bytes(signed_cache(kind, expiry))
                assert shell.load_license(machine) is None, (kind, expiry)
            for kind in ("时间卡", "试用"):
                client.return_value = signed_reply(kind, "2099-01-01 00:00:00")
                assert shell.run_cli(card, verify_only=True) == 0
                assert shell.load_license(machine) == (card, "2099-01-01 00:00:00")
            Path(shell.LIC).write_bytes(raw)
            for invalid in ("验证成功|到期时间:永久|授权类型:永久卡",
                            "验证成功|到期时间:永久|授权类型:永久卡|授权=zz",
                            reply[:-1] + ("0" if reply[-1] != "0" else "1"),
                            "验证成功|到期时间:永久|授权=" + reply.split("授权=")[-1],
                            "验证成功|到期时间:永久|授权类型:未知卡"):
                client.return_value = invalid
                with patch.object(shell, "launch_payload") as launch:
                    assert shell.run_cli(card) != 0
                    launch.assert_not_called()
                assert Path(shell.LIC).read_bytes() == raw, "坏授权不得覆盖原缓存"
            client.side_effect = OSError("模拟断网")
            assert shell.run_cli(card, verify_only=True) != 0
            client.side_effect = None
            client.return_value = "卡密已封禁"
            assert shell.run_cli(card, verify_only=True) != 0

            client.return_value = "验证成功|到期时间:永久|剩余点数:0|授权类型:点数卡"
            with patch.object(shell, "launch_payload", return_value=(True, "安全模拟启动")) as launch:
                assert shell.run_cli(card) == 0
                launch.assert_called_once()
            assert not Path(shell.LIC).exists(), "点数卡不得留下旧授权或生成新离线缓存"
            assert shell.run_cli(card, offline=True, verify_only=True) != 0
            client.return_value = reply
            assert shell.run_cli(card, verify_only=True) == 0

        tk = MagicMock()
        tk.BooleanVar.return_value.get.return_value = False
        with patch.dict(sys.modules, {"tkinter": tk}), patch.object(shell, "drop_icon"), \
                patch.object(shell.threading, "Thread"), \
                patch.object(shell, "launch_payload", return_value=(False, "测试启动失败")):
            shell.run_gui()
            callbacks = [call.args[1] for call in tk.Tk.return_value.after.call_args_list
                         if call.args[0] == 600]
            assert len(callbacks) == 1
            callbacks[0]()
            tk.Tk.return_value.destroy.assert_not_called()
            tk.StringVar.return_value.set.assert_called_with("测试启动失败")

        # 图形登录也必须走同一授权检查；缺少签名时留在登录窗口。
        tk = MagicMock()
        card_var, status_var = MagicMock(), MagicMock()
        card_var.get.return_value = card
        tk.StringVar.side_effect = [card_var, status_var]
        tk.BooleanVar.return_value.get.return_value = False
        client.return_value = "验证成功|到期时间:永久|授权类型:永久卡"
        with patch.dict(sys.modules, {"tkinter": tk}), patch.object(shell, "drop_icon"), \
                patch.object(shell.threading, "Thread") as thread, \
                patch.object(shell, "launch_payload") as launch:
            shell.run_gui()
            tk.Button.call_args_list[0].kwargs["command"]()
            thread.call_args_list[-1].kwargs["target"]()
            callbacks = [call.args[1] for call in tk.Tk.return_value.after.call_args_list
                         if call.args[0] == 0]
            assert len(callbacks) == 1
            callbacks[0]()
            launch.assert_not_called()
            tk.Tk.return_value.destroy.assert_not_called()
            tk.messagebox.showerror.assert_called_once()
            status_var.set.assert_called_with("服务器授权签名缺失或无效，请重新在线验证")

        assert not list(work.glob("fj_*.exe")), "只验证模式不得释放载荷"
        Path(shell.PAYLOAD).unlink()
        assert shell.run_cli(card, offline=True) != 0, "缺少载荷不能报告启动成功"
        Path(shell.PAYLOAD).write_bytes(b"FJPKbad")
        assert shell.launch_payload()[0] is False
        Path(shell.PAYLOAD).write_bytes(b"FJPK" + crypto.seal(shell.config.KEY, body))
        with patch.object(shell.subprocess, "Popen", side_effect=OSError("模拟进程启动失败")):
            assert shell.run_cli(card, offline=True) != 0
            client.return_value = reply
            assert shell.run_cli(card) != 0

        processes = []

        def start_test_stub(args, **kwargs):
            assert Path(args[0]).parent == work
            assert Path(args[0]).read_bytes() == body, "只允许启动本次安全 stub"
            proc = real_popen(args, **kwargs)
            processes.append(proc)
            return proc

        try:
            with patch.object(shell.subprocess, "Popen", side_effect=start_test_stub):
                ok, released = shell.launch_payload()
                assert ok, released
            assert len(processes) == 1
            assert processes[0].wait(timeout=10) == 0
        finally:
            for proc in processes:
                if proc.poll() is None:
                    proc.kill()
                proc.wait(timeout=10)
    print("授权只验证、拒绝路径、载荷失败与安全 stub 启动测试通过")


if __name__ == "__main__":
    main()
