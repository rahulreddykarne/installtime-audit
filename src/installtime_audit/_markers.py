"""Marker sets that define what counts as a dangerous install-time operation."""

from __future__ import annotations

# Files whose top-level code (and known hooks) runs during ``pip install``.
SETUP_FILENAMES = frozenset({
    "setup.py", "build.py", "_build.py", "install.py",
    "hatch_build.py", "pdm_build.py",
})

# Setuptools/distutils/backend hook methods invoked by the build system.
SETUP_HOOK_NAMES = frozenset({
    "setup", "install", "run", "build", "build_ext", "build_py",
    "develop", "egg_info", "initialize_options", "finalize_options",
})

HTTP_FETCH_CALLS = frozenset({
    "requests.get", "requests.post", "requests.request",
    "urllib.request.urlopen", "urllib.request.urlretrieve",
    "urllib3.PoolManager.request", "httpx.get", "httpx.post", "httpx.request",
    "aiohttp.ClientSession.get", "aiohttp.ClientSession.post",
})

LOW_LEVEL_NET_CALLS = frozenset({
    "socket.create_connection", "socket.socket.connect",
    "ftplib.FTP", "ftplib.FTP_TLS", "smtplib.SMTP", "smtplib.SMTP_SSL",
    "imaplib.IMAP4", "imaplib.IMAP4_SSL", "poplib.POP3", "poplib.POP3_SSL",
})

EXEC_CALLS = frozenset({
    "os.system", "os.popen", "subprocess.run", "subprocess.call",
    "subprocess.check_output", "subprocess.check_call", "subprocess.Popen",
    "os.spawnl", "os.spawnle", "os.spawnv", "os.spawnve",
})

OBFUSCATION_CALLS = frozenset({
    "base64.b64decode", "base64.urlsafe_b64decode", "binascii.a2b_base64",
    "zlib.decompress", "bz2.decompress", "lzma.decompress",
    "marshal.loads", "codecs.decode", "bytes.fromhex",
})

SENSITIVE_ENV_NAMES = frozenset({
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AZURE_STORAGE_KEY", "CI_JOB_TOKEN", "DATABASE_URL", "GITHUB_TOKEN",
    "GITLAB_TOKEN", "NPM_TOKEN", "OPENAI_API_KEY", "PIP_INDEX_URL",
    "PIP_EXTRA_INDEX_URL", "PYPI_API_TOKEN", "PYPI_PASSWORD", "PYPI_TOKEN",
    "PYPI_USERNAME", "TWINE_PASSWORD", "TWINE_USERNAME",
})

CREDENTIAL_PATH_MARKERS = frozenset({
    "/.aws/credentials", "/.aws/config", "/.docker/config.json",
    "/.kube/config", "/.netrc", "/.npmrc", "/.pypirc",
    "/.ssh/config", "/.ssh/id_dsa", "/.ssh/id_ed25519", "/.ssh/id_rsa",
})

PERSISTENCE_PATH_MARKERS = frozenset({
    "/.bash_profile", "/.bashrc", "/.config/autostart/", "/.profile",
    "/.zprofile", "/.zshrc", "/etc/cron.", "/etc/profile", "/etc/systemd/",
    "/library/launchagents/", "/library/launchdaemons/",
    "/microsoft/windows/start menu/programs/startup",
    "/programdata/microsoft/windows/start menu/programs/startup",
    "/var/spool/cron", "/windows/system32/tasks/",
})

# Text files that can smuggle a dependency-confusion index.
CONFIG_FILENAMES = frozenset({
    "setup.cfg", "pip.conf", "pip.ini", "pyproject.toml",
})
