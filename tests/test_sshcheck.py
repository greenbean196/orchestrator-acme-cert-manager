from __future__ import annotations

import inspect
import os
import socket
import time
from pathlib import Path

import paramiko
import pytest

from app import restart, sshcheck
from app.models import StepResult
from tests.conftest import make_server


def test_empty_key_path_is_actionable(layout, known_hosts):
    probs = sshcheck.validate(make_server(ssh_key_path="", ssh_known_hosts=str(known_hosts)))
    assert any("key_path is empty" in p and "orch_restart" in p for p in probs)


def test_missing_key_file(layout, known_hosts):
    probs = sshcheck.validate(make_server(ssh_key_path=str(layout["ssh"] / "nope"),
                                          ssh_known_hosts=str(known_hosts)))
    assert any("not found at" in p for p in probs)


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file modes")
def test_unreadable_key_file(layout, rsa_key, known_hosts):
    p, _ = rsa_key
    os.chmod(p, 0o000)
    try:
        probs = sshcheck.validate(make_server(ssh_key_path=str(p), ssh_known_hosts=str(known_hosts)))
    finally:
        os.chmod(p, 0o600)
    assert any("not readable" in p for p in probs)


def test_invalid_key_file(layout, known_hosts):
    p = layout["ssh"] / "junk"
    p.write_text("this is not a key\n")
    probs = sshcheck.validate(make_server(ssh_key_path=str(p), ssh_known_hosts=str(known_hosts)))
    assert any("could not be parsed" in x for x in probs)


def test_public_key_given_instead_of_private(layout, rsa_key, known_hosts):
    _, k = rsa_key
    p = layout["ssh"] / "orch_restart.pub"
    p.write_text(f"{k.get_name()} {k.get_base64()} test\n")
    probs = sshcheck.validate(make_server(ssh_key_path=str(p), ssh_known_hosts=str(known_hosts)))
    assert any("could not be parsed" in x for x in probs)


def test_passphrase_protected_key(layout, known_hosts):
    k = paramiko.RSAKey.generate(2048)
    p = layout["ssh"] / "enc"
    k.write_private_key_file(str(p), password="secret")
    probs = sshcheck.validate(make_server(ssh_key_path=str(p), ssh_known_hosts=str(known_hosts)))
    assert any("passphrase-protected" in x for x in probs)


def test_ed25519_and_ecdsa_keys_parse(layout, known_hosts):
    for cls, name in ((paramiko.Ed25519Key, "ed"), (paramiko.ECDSAKey, "ec")):
        p = layout["ssh"] / name
        if cls is paramiko.ECDSAKey:
            cls.generate().write_private_key_file(str(p))
        else:
            # paramiko cannot generate Ed25519; synthesize via cryptography
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ed25519
            pem = ed25519.Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                serialization.NoEncryption())
            p.write_bytes(pem)
        assert sshcheck.load_private_key(str(p)) is not None


def test_missing_user_and_known_hosts(layout, rsa_key):
    probs = sshcheck.validate(make_server(ssh_user="", ssh_key_path=str(rsa_key[0]), ssh_known_hosts=""))
    assert any("ssh.user is empty" in p for p in probs)
    assert any("known_hosts is empty" in p for p in probs)


def test_known_hosts_without_entry_for_host(layout, rsa_key, known_hosts):
    s = make_server(ssh_key_path=str(rsa_key[0]), ssh_known_hosts=str(known_hosts),
                    orchestrator_host="other.example.test")
    probs = sshcheck.validate(s)
    assert any("no entry for 'other.example.test'" in p for p in probs)


def test_known_hosts_entry_name_uses_port_syntax(layout, rsa_key, known_hosts):
    assert sshcheck.known_hosts_entry_name("h", 22) == "h"
    assert sshcheck.known_hosts_entry_name("h", 2222) == "[h]:2222"
    s = make_server(ssh_key_path=str(rsa_key[0]), ssh_known_hosts=str(known_hosts), ssh_port=2222)
    assert any("[orch.example.test]:2222" in p for p in sshcheck.validate(s))


def test_valid_configuration_has_no_problems(server):
    assert sshcheck.validate(server) == []


def test_authorization_probe():
    assert sshcheck.authorization_probe("sudo /bin/systemctl reload nginx") == \
        "sudo -n -l /bin/systemctl reload nginx"
    assert sshcheck.authorization_probe("sudo -n /bin/systemctl restart --no-block gms.service") == \
        "sudo -n -l /bin/systemctl restart --no-block gms.service"
    assert sshcheck.authorization_probe("/usr/sbin/service gms restart") is None
    assert sshcheck.authorization_probe("") is None


# --------------------------------------------------------------------------- paramiko stand-ins

class _FakeEvent:
    """Stand-in for Channel.status_event: never blocks, records every wait()."""

    def __init__(self):
        self.waits = []

    def wait(self, timeout=None):
        self.waits.append(timeout)
        return True


class _FakeChannel:
    """Stand-in for paramiko.Channel: serves stdout/stderr in recv()-sized chunks.

    With ``hang=True`` the exit status never becomes ready, so sshcheck.run()
    has to give up on its own deadline.
    """

    def __init__(self, rc, out, err, hang=False):
        self._rc = rc
        self._o = out if isinstance(out, bytes) else out.encode()
        self._e = err if isinstance(err, bytes) else err.encode()
        self._hang = hang
        self.status_event = _FakeEvent()
        self.recv_sizes = []
        self.recv_stderr_sizes = []
        self.closed = False

    def recv_ready(self):
        return bool(self._o)

    def recv_stderr_ready(self):
        return bool(self._e)

    def recv(self, n):
        self.recv_sizes.append(n)
        d, self._o = self._o[:n], self._o[n:]
        return d

    def recv_stderr(self, n):
        self.recv_stderr_sizes.append(n)
        d, self._e = self._e[:n], self._e[n:]
        return d

    def exit_status_ready(self):
        return not self._hang

    def close(self):
        self.closed = True

    def recv_exit_status(self):
        return self._rc


class _FakeFile:
    """The stdout/stderr file objects exec_command returns; run() only uses .channel."""

    def __init__(self, channel):
        self.channel = channel


class _FakeClient:
    """Minimal stand-in for paramiko.SSHClient as sshcheck.run drives it.

    ``responses`` is consumed one entry per exec_command(): a ``(rc, stdout, stderr)``
    tuple to answer with (str or bytes output), or an exception instance to raise
    from exec_command itself.
    """

    def __init__(self, responses, hang=False):
        self.responses = list(responses)
        self.hang = hang
        self.commands = []
        self.exec_timeouts = []
        self.channels = []
        self.closed = False

    def exec_command(self, cmd, timeout=None):
        self.commands.append(cmd)
        self.exec_timeouts.append(timeout)
        resp = self.responses.pop(0)
        if isinstance(resp, BaseException):
            raise resp
        chan = _FakeChannel(*resp, hang=self.hang)
        self.channels.append(chan)
        return None, _FakeFile(chan), _FakeFile(chan)

    def close(self):
        self.closed = True


class _RecordingSSHClient(_FakeClient):
    """_FakeClient plus the SSHClient surface sshcheck.connect() drives, recording every call."""

    def __init__(self, responses=(), connect_error=None, load_error=None):
        super().__init__(responses)
        self.calls = []
        self.host_keys_path = None
        self.policy = None
        self.connect_kwargs = None
        self.connect_error = connect_error
        self.load_error = load_error

    def load_host_keys(self, filename):
        self.calls.append("load_host_keys")
        if self.load_error is not None:
            raise self.load_error
        self.host_keys_path = filename

    def set_missing_host_key_policy(self, policy):
        self.calls.append("set_missing_host_key_policy")
        self.policy = policy

    def connect(self, **kwargs):
        self.calls.append("connect")
        self.connect_kwargs = kwargs
        if self.connect_error is not None:
            raise self.connect_error


class _SSHClientFactory:
    """What paramiko.SSHClient is swapped for: builds _RecordingSSHClient instances from its settings."""

    def __init__(self):
        self.responses = []
        self.connect_error = None
        self.load_error = None
        self.clients = []

    def __call__(self):
        c = _RecordingSSHClient(self.responses, self.connect_error, self.load_error)
        self.clients.append(c)
        return c

    @property
    def client(self):
        assert len(self.clients) == 1, f"expected exactly one SSHClient, got {len(self.clients)}"
        return self.clients[0]


@pytest.fixture
def ssh_factory(monkeypatch):
    """Replace paramiko.SSHClient with a recording fake and make AutoAddPolicy unusable."""
    factory = _SSHClientFactory()
    monkeypatch.setattr(paramiko, "SSHClient", factory)

    class _NoAutoAdd:
        def __init__(self, *a, **k):
            raise AssertionError("AutoAddPolicy must never be used: host keys are pinned in known_hosts")

    monkeypatch.setattr(paramiko, "AutoAddPolicy", _NoAutoAdd)
    return factory


# --------------------------------------------------------------------------- connect() / test_connection()

def test_connect_loads_known_hosts_and_rejects_unknown_host_keys(server, ssh_factory):
    client = sshcheck.connect(sshcheck.Endpoint.of(server))
    assert client is ssh_factory.client
    assert client.host_keys_path == server.ssh_known_hosts
    assert isinstance(client.policy, paramiko.RejectPolicy)
    # host keys are loaded and the policy pinned *before* any network activity
    assert client.calls == ["load_host_keys", "set_missing_host_key_policy", "connect"]
    src = inspect.getsource(sshcheck)
    assert "AutoAddPolicy" not in src and "WarningPolicy" not in src


def test_connect_passes_configured_parameters(layout, rsa_key, ssh_factory):
    p, k = rsa_key
    kh = layout["ssh"] / "known_hosts_2222"
    kh.write_text(f"[orch.example.test]:2222 {k.get_name()} {k.get_base64()}\n")
    s = make_server(ssh_user="svc", ssh_port=2222, ssh_key_path=str(p), ssh_known_hosts=str(kh))

    sshcheck.connect(sshcheck.Endpoint.of(s))

    kw = ssh_factory.client.connect_kwargs
    assert kw["hostname"] == "orch.example.test"
    assert kw["port"] == 2222 and isinstance(kw["port"], int)
    assert kw["username"] == "svc"
    assert kw["pkey"].get_fingerprint() == k.get_fingerprint()
    assert kw["timeout"] == kw["banner_timeout"] == kw["auth_timeout"] == sshcheck._CONNECT_TIMEOUT
    assert kw["allow_agent"] is False
    assert kw["look_for_keys"] is False
    assert "password" not in kw
    assert ssh_factory.client.host_keys_path == str(kh)


def test_connect_loads_rsa_key(server, rsa_key, ssh_factory):
    sshcheck.connect(sshcheck.Endpoint.of(server))
    pkey = ssh_factory.client.connect_kwargs["pkey"]
    assert isinstance(pkey, paramiko.RSAKey)
    assert pkey.get_fingerprint() == rsa_key[1].get_fingerprint()


def test_connect_loads_ecdsa_key(layout, known_hosts, ssh_factory):
    ec = paramiko.ECDSAKey.generate()
    p = layout["ssh"] / "orch_ec"
    ec.write_private_key_file(str(p))
    s = make_server(ssh_key_path=str(p), ssh_known_hosts=str(known_hosts))

    sshcheck.connect(sshcheck.Endpoint.of(s))

    pkey = ssh_factory.client.connect_kwargs["pkey"]
    assert isinstance(pkey, paramiko.ECDSAKey)
    assert pkey.get_fingerprint() == ec.get_fingerprint()


def test_test_connection_missing_key_is_clear_and_never_dials(layout, known_hosts, ssh_factory):
    missing = layout["ssh"] / "does_not_exist"
    res = sshcheck.test_connection(make_server(ssh_key_path=str(missing), ssh_known_hosts=str(known_hosts)))
    assert not res.ok
    assert res.detail == {"phase": "connect"}
    assert f"private key not found at {missing}" in res.message
    assert "Errno" not in res.message and "Traceback" not in res.message
    assert ssh_factory.clients == []


def test_test_connection_unreadable_key_is_clear_and_never_dials(server, ssh_factory, monkeypatch):
    key = Path(server.ssh_key_path)

    class _Os:
        """os with read access denied on the key (chmod cannot prove this when the tests run as root)."""

        def __getattr__(self, name):
            return getattr(os, name)

        @staticmethod
        def access(path, mode):
            if Path(path) == key and mode & os.R_OK:
                return False
            return os.access(path, mode)

    monkeypatch.setattr(sshcheck, "os", _Os())
    res = sshcheck.test_connection(server)
    assert not res.ok
    assert res.detail == {"phase": "connect"}
    assert f"private key at {key} is not readable by the service user" in res.message
    assert "ownership/permissions" in res.message
    assert ssh_factory.clients == []


def test_connect_wraps_known_hosts_load_failure(server, ssh_factory):
    ssh_factory.load_error = OSError("disk on fire")
    with pytest.raises(sshcheck.SSHConfigError, match=f"cannot load known_hosts {server.ssh_known_hosts}: disk on fire"):
        sshcheck.connect(sshcheck.Endpoint.of(server))
    assert "connect" not in ssh_factory.client.calls


_HOST = "orch.example.test"


@pytest.mark.parametrize("make_exc, expected", [
    (lambda k: paramiko.BadHostKeyException(_HOST, k, k),
     [f"SSH host key for {_HOST} does not match the pinned entry in {{known_hosts}}",
      "never disable host-key checking"]),
    (lambda k: paramiko.AuthenticationException("Authentication failed."),
     [f"SSH authentication failed for admin@{_HOST}", "{key} is not in that account's authorized_keys"]),
    (lambda k: paramiko.SSHException(f"Server '{_HOST}' not found in known_hosts"),
     [f"SSH host key for {_HOST} is not pinned in {{known_hosts}}", "verifying the fingerprint"]),
    (lambda k: paramiko.SSHException("Error reading SSH protocol banner"),
     [f"SSH negotiation with {_HOST} failed: Error reading SSH protocol banner"]),
    (lambda k: socket.timeout("timed out"),
     [f"SSH connection to {_HOST} timed out after {sshcheck._CONNECT_TIMEOUT}s."]),
    (lambda k: ConnectionRefusedError(111, "Connection refused"),
     [f"SSH connection to {_HOST} failed:", "Connection refused"]),
], ids=["bad-host-key", "auth-failed", "host-key-not-pinned", "ssh-negotiation", "socket-timeout", "os-error"])
def test_test_connection_maps_connect_errors_to_operator_messages(server, rsa_key, ssh_factory, make_exc, expected):
    ssh_factory.connect_error = make_exc(rsa_key[1])

    res = sshcheck.test_connection(server)

    assert isinstance(res, StepResult) and not res.ok
    assert res.detail == {"phase": "connect"}
    for fragment in expected:
        assert fragment.format(known_hosts=server.ssh_known_hosts, key=server.ssh_key_path) in res.message
    assert "Traceback" not in res.message
    client = ssh_factory.client
    assert client.calls == ["load_host_keys", "set_missing_host_key_policy", "connect"]
    assert client.closed, "a client whose connect() failed must be closed"
    assert client.commands == [], "nothing may be executed when the connection failed"


def test_classify_connect_error_uses_port_syntax_for_non_default_port(server):
    ep = sshcheck.Endpoint.of(server)
    ep.port = 2222
    msg = sshcheck.classify_connect_error(socket.timeout(), ep)
    assert f"SSH connection to [{_HOST}]:2222 timed out after {sshcheck._CONNECT_TIMEOUT}s." == msg
    msg = sshcheck.classify_connect_error(paramiko.AuthenticationException(), ep)
    assert f"admin@[{_HOST}]:2222" in msg


def test_test_connection_without_activation_commands_never_dials(layout, rsa_key, known_hosts, ssh_factory):
    s = make_server(ssh_key_path=str(rsa_key[0]), ssh_known_hosts=str(known_hosts),
                    restart_command="", nginx_reload_command="")
    res = sshcheck.test_connection(s)
    assert not res.ok
    assert "nothing would activate the certificate" in res.message
    assert ssh_factory.clients == []


def test_test_connection_end_to_end_through_fake_paramiko(server, ssh_factory):
    ssh_factory.responses = [(0, "(root) NOPASSWD: /bin/systemctl restart --no-block gms.service", ""),
                             (0, "(root) NOPASSWD: /bin/systemctl reload nginx", "")]

    res = sshcheck.test_connection(server)

    assert res.ok and "without a password" in res.message
    client = ssh_factory.client
    assert client.calls == ["load_host_keys", "set_missing_host_key_policy", "connect"]
    assert client.connect_kwargs["username"] == "admin"
    assert client.commands == ["sudo -n -l systemctl restart --no-block gms.service",
                               "sudo -n -l systemctl reload nginx"]
    assert client.exec_timeouts == [sshcheck._CMD_TIMEOUT, sshcheck._CMD_TIMEOUT]
    assert res.detail["phase"] == "authorize"
    assert [c["label"] for c in res.detail["checks"]] == ["restart_command", "nginx_reload_command"]
    assert client.closed


def test_test_connection_reports_config_problems_without_connecting(layout, known_hosts, monkeypatch):
    called = []
    monkeypatch.setattr(paramiko.SSHClient, "connect", lambda *a, **k: called.append(1))
    res = sshcheck.test_connection(make_server(ssh_key_path="", ssh_known_hosts=str(known_hosts)))
    assert not res.ok and "key_path is empty" in res.message
    assert called == []


def test_test_connection_sudo_password_required(server, monkeypatch):
    fake = _FakeClient([(1, "", "sudo: a password is required"), (0, "/bin/systemctl reload nginx", "")])
    monkeypatch.setattr(sshcheck, "open_client", lambda s: fake)
    res = sshcheck.test_connection(server)
    assert not res.ok
    assert "NOPASSWD" in res.message
    assert fake.commands[0].startswith("sudo -n -l ")
    assert fake.closed


def test_test_connection_success(server, monkeypatch):
    fake = _FakeClient([(0, "/bin/systemctl restart --no-block gms.service", ""),
                        (0, "/bin/systemctl reload nginx", "")])
    monkeypatch.setattr(sshcheck, "open_client", lambda s: fake)
    res = sshcheck.test_connection(server)
    assert res.ok and "without a password" in res.message
    assert len(res.detail["checks"]) == 2


def test_connect_error_classification(server):
    bad = paramiko.AuthenticationException("Authentication failed.")
    assert "authorized_keys" in sshcheck._classify_connect_error(bad, server)
    hk = paramiko.SSHException("Server 'x' not found in known_hosts")
    assert "not pinned" in sshcheck._classify_connect_error(hk, server)
    assert "timed out" in sshcheck._classify_connect_error(__import__("socket").timeout(), server)


# --------------------------------------------------------------------------- run()

class _Clock:
    """A fake time.monotonic that advances by ``step`` seconds per call."""

    def __init__(self, start=1000.0, step=1.0):
        self.now = start
        self.step = step

    def __call__(self):
        t = self.now
        self.now += self.step
        return t


def test_run_raises_socket_timeout_when_exit_status_never_ready(monkeypatch):
    fake = _FakeClient([(0, "partial output", "")], hang=True)
    monkeypatch.setattr(time, "monotonic", _Clock())

    with pytest.raises(socket.timeout, match=r"command did not finish within 3s: 'sleep 999'"):
        sshcheck.run(fake, "sleep 999", timeout=3)

    chan = fake.channels[0]
    assert chan.closed, "a hung channel must be closed so the transport is not left dangling"
    # deadline = t0 + 3 with one clock tick per loop: two 0.5s polls, then the third check trips the deadline
    assert chan.status_event.waits == [0.5, 0.5]
    assert fake.exec_timeouts == [3], "the channel-level timeout must match the deadline"
    assert chan.recv_sizes, "output produced before the hang is still drained while waiting"


def test_run_drains_output_larger_than_one_recv_in_chunks():
    big_out = b"o" * (2 * 65536 + 7)
    big_err = b"e" * (65536 + 1)
    fake = _FakeClient([(0, big_out + b"\n", big_err + b"\n")])

    rc, out, err = sshcheck.run(fake, "cat big")

    assert rc == 0
    assert out == big_out.decode() and len(out) == 2 * 65536 + 7
    assert err == big_err.decode() and len(err) == 65536 + 1
    chan = fake.channels[0]
    assert chan.recv_sizes == [65536, 65536, 65536]
    assert chan.recv_stderr_sizes == [65536, 65536]
    assert not chan._o and not chan._e, "every byte must be drained"


def test_run_returns_exit_status_and_replaces_undecodable_bytes():
    fake = _FakeClient([(3, b"ok\xff\xfe\n", b" warn \n")])
    rc, out, err = sshcheck.run(fake, "x")
    assert rc == 3
    assert out == "ok��"
    assert err == "warn"
    assert fake.exec_timeouts == [sshcheck._CMD_TIMEOUT]


# --------------------------------------------------------------------------- probe_commands()

def test_probe_commands_entries_carry_labels():
    fake = _FakeClient([(0, "(root) NOPASSWD: /bin/systemctl restart --no-block gms.service", ""),
                        (0, "(root) NOPASSWD: /bin/systemctl reload nginx", "")])
    commands = [
        ("restart_command", "sudo /bin/systemctl restart --no-block gms.service"),
        ("nginx_reload_command", "sudo /bin/systemctl reload nginx"),
        ("unset_command", ""),
        ("plain_command", "/usr/sbin/service gms restart"),
    ]

    ok, checks = sshcheck.probe_commands(fake, "admin", commands)

    assert ok is True
    assert [c["label"] for c in checks] == ["restart_command", "nginx_reload_command", "plain_command"]
    assert all("label" in c and "command" in c and "ok" in c for c in checks)
    assert [c["command"] for c in checks] == [cmd for _, cmd in commands if cmd]

    restart_check, nginx_check, plain_check = checks
    assert restart_check["probe"] == "sudo -n -l /bin/systemctl restart --no-block gms.service"
    assert nginx_check["probe"] == "sudo -n -l /bin/systemctl reload nginx"
    assert restart_check["exit"] == 0 and restart_check["ok"] is True
    assert "NOPASSWD" in restart_check["stdout"] and restart_check["stderr"] == ""
    assert "hint" not in restart_check
    # a command that does not go through sudo is reported, not executed
    assert plain_check == {"label": "plain_command", "command": "/usr/sbin/service gms restart",
                           "ok": True, "note": "not using sudo; authorization not probed"}
    assert fake.commands == [restart_check["probe"], nginx_check["probe"]]


def test_probe_commands_failures_carry_labels_hints_and_errors():
    fake = _FakeClient([
        (1, "", "sudo: a password is required"),
        (1, "Sorry, user admin is not allowed to execute '/bin/systemctl reload nginx' as root on orch." + "x" * 600, ""),
        paramiko.SSHException("SSH session not active"),
        socket.timeout("command did not finish within 30s: 'sudo -n -l /bin/true'"),
    ])
    commands = [
        ("restart_command", "sudo /bin/systemctl restart --no-block gms.service"),
        ("nginx_reload_command", "sudo /bin/systemctl reload nginx"),
        ("dropped", "sudo /bin/false"),
        ("hung", "sudo /bin/true"),
    ]

    ok, checks = sshcheck.probe_commands(fake, "admin", commands)

    assert ok is False
    assert [c["label"] for c in checks] == ["restart_command", "nginx_reload_command", "dropped", "hung"]
    assert [c["ok"] for c in checks] == [False, False, False, False]

    password, denied, dropped, hung = checks
    assert password["exit"] == 1
    assert "sudo wants a password for admin" in password["hint"] and "NOPASSWD" in password["hint"]
    assert denied["hint"] == "sudoers does not permit this exact command for this user."
    assert len(denied["stdout"]) == 500, "captured output is truncated for the result detail"
    assert dropped == {"label": "dropped", "command": "sudo /bin/false", "ok": False,
                       "error": "probe failed: SSH session not active"}
    assert hung["label"] == "hung" and hung["error"].startswith("probe failed: command did not finish within 30s")
    assert "probe" not in dropped and "exit" not in hung
    # every probe was attempted, in order, even after earlier failures
    assert fake.commands == ["sudo -n -l /bin/systemctl restart --no-block gms.service",
                             "sudo -n -l /bin/systemctl reload nginx",
                             "sudo -n -l /bin/false",
                             "sudo -n -l /bin/true"]


def test_restart_preflight_blocks_before_any_network(layout, known_hosts, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("must not be reached")
    monkeypatch.setattr(restart, "_deployed_serial", boom)
    res = restart.restart(make_server(ssh_key_path="", ssh_known_hosts=str(known_hosts)))
    assert isinstance(res, StepResult) and not res.ok
    assert res.detail["phase"] == "preflight"
    assert "key_path is empty" in res.message
