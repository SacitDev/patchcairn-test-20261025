"""PatchCairn path rules (layer L0, standard library only).

One relative-path grammar, the portable-path test, the collision key, the
display escaper, the protected-name policy and the system-root list. These
functions classify text only; they never open, resolve or list anything, so
callers pass the backend's pinned final path, and the backends refuse links,
reparse points and alternate spellings of a stored name.

Limits are the intersection of the validators they replace, so a path accepted
here is accepted by every backend and can be restored on Windows, Linux and macOS:
  - a relative path has at most 200 UTF-16 code units (the Windows helper and
    adapter) and at most 64 components (the POSIX and Windows adapters);
  - a name has at most 255 UTF-8 bytes (the POSIX adapter; this also keeps it
    within NTFS's 255 UTF-16 units);
  - names are used exactly as given, without Unicode normalisation (as today);
    casefold_key() folds case and NFC/NFD forms for collision checks.
"""
from __future__ import annotations

import os
from pathlib import PurePosixPath
import re
import unicodedata

MAX_PATH_UNITS = 200
MAX_PARTS = 64
MAX_NAME_BYTES = 255
_FORBIDDEN = frozenset('\\/:*?"<>|')
# Windows treats the superscript digits 1-3 as digits in COM and LPT device names.
_RESERVED = re.compile("(?i:con|prn|aux|nul|conin\\$|conout\\$|com[0-9\u00b9\u00b2\u00b3]|lpt[0-9\u00b9\u00b2\u00b3])")
# An 8.3 alias such as PROGRA~1 can name a system or private folder under another spelling.
_SHORT_NAME = re.compile(r"(?=[^.]{1,8}(?:\.|\Z))[^.~]{1,6}~[0-9]{1,6}(?:\.[^.]{1,3})?")
# Mac OS Extended ignores these code points when it compares names, so ".s<ZWNJ>sh" opens ".ssh".
_IGNORABLE = re.compile("[\u200c-\u200f\u202a-\u202e\u206a-\u206f\ufeff]")
_DRIVE = re.compile(r"[A-Za-z]:[\\/]")
_SEPARATORS = re.compile(r"[\\/]")
_UID = re.compile(r"[0-9]{1,10}")
_DISPLAY_ESCAPED = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})

PROTECTED_COMPONENTS = frozenset({
    ".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", ".git", ".password-store",
    "appdata", "keychains", "keychain", "credentials", "credential",
    "passwords", "password", "secrets", "secret", "vault", "wallets",
    "google-chrome", "chromium", "chrome", "firefox", "mozilla", "edge",
    "brave", "brave-browser", "safari", "opera", "vivaldi", "tor browser",
    "chatgpt", "chats", "chat", "sessions", "session", "conversation",
    "conversations", ".codex", ".claude", ".gemini", "signal", "telegram",
    "discord", "slack", "teams", "whatsapp", "keyrings", "keyring", "kwalletd", "kwallet",
    "keepass", "keepassxc", "1password", "bitwarden", "lastpass", "enpass", "dashlane",
    "gnome-keyring", "gcloud", "gh", "git-credential-manager", "git", "rclone",
    "identityservice", "identitycache", "microsoft.aad.brokerplugin", "microsoftaccounts",
    "globalstorage", "workspacestorage", "chatsessions",
    # Deleted files and restore points, wherever a drive is mounted.
    "$recycle.bin", "system volume information", ".trash", ".trashes",
    # Saved Wi-Fi and VPN keys (NetworkManager) and macOS account password hashes.
    "system-connections", "dslocal",
    # The partitions of a Samba domain controller's account database, also inside a samba-tool backup.
    "sam.ldb.d",
})
PROTECTED_FILES = frozenset({
    ".env", ".npmrc", ".pypirc", ".netrc", "_netrc", ".pgpass", "id_rsa", "id_dsa",
    "id_ecdsa", "id_ed25519", "authorized_keys", "known_hosts", "cookies",
    "cookies.sqlite", "history", "history.db", "login data", "web data",
    "key4.db", "logins.json", "cert9.db", "credential.json", "credentials.json",
    "token.json", "tokens.json", "auth.json", "secrets.json", "passwords.json",
    ".git-credentials", ".gitconfig", ".bash_history", ".zsh_history", ".python_history",
    ".psql_history", "consolehost_history.txt", "state.vscdb", "access_tokens.db",
    "credentials.db", "application_default_credentials.json",
    "wpa_supplicant.conf", "krb5.keytab", "chap-secrets", "pap-secrets", "ipsec.secrets",
    # strongSwan's swanctl.conf (its secrets section holds pre-shared keys and passwords), Libreswan's NSS password
    # and the .secrets file of local CI runners (act).
    "swanctl.conf", "nsspassword", ".secrets",
    # Cargo, Terraform and OpenTofu registry tokens (CLI configuration files hold credentials blocks), the HashiCorp
    # Vault token and Bitcoin-style wallets.
    "credentials.toml", "credentials.tfrc.json", ".terraformrc", "terraform.rc", ".tofurc", "tofurc", "tofu.rc",
    ".vault-token", "wallet.dat",
    # Password databases wherever they were copied: Samba's (any layout) and winbind's offline-logon cache, an
    # Active Directory domain controller's and an AD LDS instance's, earlier Linux password hashes
    # (/etc/security/opasswd) and the old NSS key database (Firefox, Libreswan).
    "secrets.tdb", "passdb.tdb", "secrets.ldb", "sam.ldb", "winbindd_cache.tdb", "ntds.dit", "adamntds.dit",
    "opasswd", "key3.db",
})
# .env.local, .Trash-1000, renamed copies of a wallet or an AD database (wallet.dat.bak, ntds.dit.old) and
# Ethereum key files (UTC--<time>--<address>).
PROTECTED_PREFIXES = (".env.", ".trash-", "wallet.dat.", "ntds.dit.", "utc--")
# .secrets: per-connection IPsec secrets (ipsec.d/*.secrets); .tfrc: a Terraform or OpenTofu CLI configuration file.
PROTECTED_SUFFIXES = frozenset({".pem", ".key", ".pfx", ".p12", ".kdbx", ".kdb", ".keyring", ".wallet",
                                ".jks", ".keystore", ".keychain", ".keychain-db", ".ppk", ".gpg", ".asc", ".keytab",
                                ".secrets", ".tfrc"})
BROWSER_PREFIXES = ("google-chrome", "microsoft-edge", "edge", "chrome", "chromium",
                    "firefox", "mozilla", "brave", "brave-browser", "safari", "opera", "vivaldi")
# Name sequences that are private wherever they appear, for example in a copy of another system's disk: messages,
# password hashes (Linux, BSD, macOS, Samba's private folders, SSSD's login cache), SSH host keys, Wi-Fi and VPN keys
# (wpa_supplicant, iwd, WireGuard on Linux and Windows, IPsec ipsec.d and swanctl), the Windows account database and
# its old copies in Windows\repair (RegBack too), Windows protected keys, sops age keys (in the default folders, and
# keys.txt under any configuration folder) and Ethereum key folders. Each names a system location, so a folder merely
# named wpa_supplicant, Microsoft, Samba/Private or Windows/Repair inside a person's files stays readable.
PROTECTED_SEQUENCES = (("library", "messages"), (".local", "share", "trash"), ("etc", "shadow"), ("etc", "shadow-"),
                       ("etc", "gshadow"), ("etc", "gshadow-"), ("etc", "master.passwd"), ("etc", "spwd.db"),
                       ("samba", "smbpasswd"), ("private", "smbpasswd"), ("etc", "samba", "private"),
                       ("var", "lib", "samba", "private"), ("usr", "local", "samba", "private"),
                       ("samba4", "private"), ("var", "lib", "sss", "db"), ("var", "db", "sss"),
                       ("etc", "ssh"), ("etc", "wpa_supplicant"), ("var", "lib", "iwd"), ("etc", "wireguard"),
                       ("wireguard", "data", "configurations"), ("ipsec.d", "private"),
                       *(("swanctl", keys) for keys in ("private", "rsa", "ecdsa", "bliss", "pkcs8", "pkcs12",
                                                        "conf.d")),
                       ("system32", "config"),
                       *((system, "repair", hive) for system in ("windows", "winnt")
                         for hive in ("sam", "security", "system", "software", "regback")),
                       ("microsoft", "protect"), ("microsoft", "crypto"),
                       (".config", "sops", "age"), ("application support", "sops", "age"), ("sops", "age", "keys.txt"),
                       (".ethereum", "keystore"), ("ethereum", "keystore"))
# A domain controller's NTDS folder holds the directory database (ntds.dit, a protected name anywhere, and renamed
# copies such as ntds_old.dit or ntds.dit.bak kept after an offline defragmentation) and its engine files: the
# checkpoint, the reserve and rotating transaction logs (edb0001a.log), the flush map and temp.edb. Matching them by
# file type, also in subfolders such as dsadata.bak, keeps a person's notes in a folder named Windows/NTDS readable;
# protected_root refuses the folder itself.
NTDS_FOLDERS = (("windows", "ntds"), ("winnt", "ntds"))
NTDS_SUFFIXES = frozenset({".dit", ".bak", ".old", ".chk", ".log", ".jrs", ".jfm", ".edb"})
# Matched only as the leading components of an absolute path, so ordinary folders named dev, etc or
# windows inside a selection stay readable.
WINDOWS_SYSTEM_ROOTS = frozenset({"windows", "program files", "program files (x86)", "program files (arm)",
                                  "programdata", "system volume information", "$recycle.bin", "recovery",
                                  "windows.old"})
POSIX_SYSTEM_ROOTS = frozenset({"usr", "var", "opt", "etc", "bin", "sbin", "boot", "efi", "dev", "proc", "sys", "run",
                                "snap", "nix", "private", "system", "library", "applications"})
# macOS resolves /tmp, /var/tmp and /var/folders to the same names under /private, so both spellings count.
TEMPORARY_PREFIXES = (("dev", "shm"), ("tmp",), ("var", "tmp"), ("private", "tmp"), ("private", "var", "tmp"),
                      ("var", "folders"), ("private", "var", "folders"))


class PathRefusal(ValueError):
    """A path or name outside the one grammar; ``code`` is categorical.

    It has the shape of pc_records.Refusal (a ValueError with ``code``) but cannot subclass it: this
    layer imports no product module, and ``except`` matches only real base classes. Callers catch
    ValueError, or use scoped_base.relative_path, which turns it into a Refusal.
    """

    def __init__(self, code, message=None):
        self.code = code
        super().__init__(code if message is None else message)


def _name_problem(name):
    if name in ("", ".", ".."):
        return "invalid-path-component", "Empty, '.' and '..' components are not accepted"
    if any(ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF or char in _FORBIDDEN for char in name):
        return "invalid-path-component", "A name contains a control, separator, stream or wildcard character"
    if name[-1] in ". ":
        return "invalid-path-component", "A name cannot end in a dot or a space"
    if len(name.encode("utf-8")) > MAX_NAME_BYTES:
        return "invalid-path-component", "A name is longer than 255 bytes"
    if _RESERVED.fullmatch(name.split(".", 1)[0].rstrip(" ")):
        return "reserved-path-component", "Windows reserved device names are not accepted"
    return None


def _path_problem(value):
    if not isinstance(value, str) or not value:
        return "invalid-relative-path", "A non-empty relative path is required"
    if value.startswith("/") or "\\" in value:
        return "invalid-relative-path", "Only forward-slash relative paths are accepted"
    if len(value.encode("utf-16-le", "surrogatepass")) > 2 * MAX_PATH_UNITS:
        return "path-too-long", "The path is longer than 200 characters"
    parts = value.split("/")
    if len(parts) > MAX_PARTS:
        return "path-too-long", "The path has more than 64 components"
    for part in parts:
        problem = _name_problem(part)
        if problem:
            return problem
    return None


def relative(p):
    """Return ``p`` unchanged if it is a relative path in the one grammar; raise PathRefusal otherwise.

    Codes: invalid-relative-path (shape), path-too-long, invalid-path-component, reserved-path-component.
    """
    problem = _path_problem(p)
    if problem:
        raise PathRefusal(*problem)
    return p


def portable(p):
    """True if the relative path ``p`` can be stored on Windows, Linux and macOS.

    A listing asks portable(parent + "/" + name). Entries that fail are reported
    as "not included" and never read; only an explicit selection of one is refused.
    """
    return isinstance(p, str) and _path_problem(p) is None


def casefold_key(p):
    """Collision key: names that differ only in case or in NFC/NFD form share a key."""
    if not isinstance(p, str):
        raise TypeError("casefold_key needs text")
    return unicodedata.normalize("NFC", unicodedata.normalize("NFD", p).casefold())


def display(text):
    """Text safe to show the owner: control, format, separator, surrogate and unassigned characters and
    the backslash become \\uXXXX escapes, so a name cannot hide or reorder what the owner reads."""
    if not isinstance(text, str):
        raise TypeError("display needs text")
    return "".join(
        (f"\\u{ord(char):04x}" if ord(char) <= 0xFFFF else f"\\U{ord(char):08x}")
        if char == "\\" or unicodedata.category(char) in _DISPLAY_ESCAPED else char
        for char in text)


def _windows(parts):
    if parts and parts[-1] == "":
        parts = parts[:-1]
    # Windows ignores trailing dots and spaces, opens streams after ':' and resolves 8.3 aliases, so such
    # spellings could reach a system folder under another name; refuse them instead of guessing.
    if any(_name_problem(part) or _SHORT_NAME.fullmatch(part) for part in parts):
        return None
    return "windows", parts


def _posix(parts):
    if parts and parts[-1] == "":
        parts = parts[:-1]
    return None if any(part in ("", ".", "..") for part in parts) else ("posix", parts)


def _drive_letter(name):
    return len(name) == 1 and name.isascii() and name.isalpha()


def _posix_root(parts):
    """A POSIX path's components, with a Windows drive reached through WSL or Git Bash checked as Windows."""
    split = _posix(parts)
    if split is None:
        return None
    parts = split[1]
    # WSL mounts each Windows drive at /mnt/<letter>; Git Bash and some WSL setups use /<letter>.
    if len(parts) >= 2 and parts[0] == "mnt" and _drive_letter(parts[1]):
        return _windows(parts[2:])
    if parts and _drive_letter(parts[0]):
        return _windows(parts[1:])
    return split


def _split_absolute(path):
    """('windows' | 'posix', components) for a plain absolute path, or None."""
    try:
        raw = os.fspath(path)
    except TypeError:
        return None
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        return None
    if raw.startswith("\\\\"):
        pieces = _SEPARATORS.split(raw[2:])
        # Device namespaces (\\?\, \\.\) bypass Win32 name rules; administrative shares (C$, ADMIN$) reach
        # whole drives and the Windows folder; a UNC path needs a server and a share.
        if len(pieces) < 2 or pieces[0] in ("", "?", ".") or not pieces[1] or pieces[1].endswith("$"):
            return None
        # \\wsl$\<distribution>\... is that distribution's own root, Windows drives under /mnt included.
        if pieces[0].casefold() in ("wsl$", "wsl.localhost"):
            return _posix_root(pieces[2:])
        return _windows(pieces[2:])
    if _DRIVE.match(raw):
        return _windows(_SEPARATORS.split(raw[3:]))
    # Only two leading backslashes make a UNC path; '//' is '/' on Linux and macOS, and a backslash in a
    # rooted spelling can be a UNC path on Windows, so both are refused.
    if not raw.startswith("/") or "\\" in raw:
        return None
    return _posix_root(raw[1:].split("/"))


def _temporary_length(parts):
    for prefix in TEMPORARY_PREFIXES:
        if tuple(parts[:len(prefix)]) == prefix:
            return len(prefix)
    if parts[:2] == ["run", "user"] and len(parts) > 2 and _UID.fullmatch(parts[2]):
        return 3
    return 0


def _windows_system(parts):
    return not parts or parts[0].casefold() in WINDOWS_SYSTEM_ROOTS


def is_system_root(abs_path):
    """True for a whole volume, a system folder or anything under one.

    Fails closed: anything that is not a plain absolute path is also True.
    """
    split = _split_absolute(abs_path)
    if split is None:
        return True
    flavor, parts = split
    if flavor == "windows":
        return _windows_system(parts)
    if not parts:
        return True
    # On WSL /mnt holds every Windows drive and /mnt/wsl the disks that wsl --mount attaches. A path cannot tell WSL
    # from another Linux, so both folders are refused on every system; a drive or folder below them is checked as
    # usual. /mnt/wslg and everything below it is WSLg's own runtime folder (sockets, logs and a view of the
    # distribution), so all of it is refused.
    mount = [part.casefold() for part in parts[:2]]
    if (len(parts) <= 2 and mount in (["mnt"], ["mnt", "wsl"])) or mount == ["mnt", "wslg"]:
        return True
    if _temporary_length(parts):
        return False
    # udisks mounts removable drives at /run/media/<user>/<label> on Fedora, Arch and openSUSE.
    if parts[:2] == ["run", "media"] and len(parts) >= 4:
        return False
    # On a Windows host a rooted path such as /Windows./System32 or /Windows::$INDEX_ALLOCATION opens C:\Windows,
    # and an 8.3 alias such as /PROGRA~1 opens C:\Program Files; any 8.3-shaped first name is refused.
    lead = parts[0].split(":", 1)[0].rstrip(". ").casefold()
    return (lead in POSIX_SYSTEM_ROOTS or lead in WINDOWS_SYSTEM_ROOTS or lead.startswith("lib")
            or bool(_SHORT_NAME.fullmatch(lead)))


def _root_names(abs_path):
    split = _split_absolute(abs_path)
    if split is None:
        return None
    flavor, parts = split
    return parts[_temporary_length(parts):] if flavor == "posix" else parts


def _matches(names, *, selected_root=False):
    folded = []
    for name in names:
        name = _IGNORABLE.sub("", name)
        if _SHORT_NAME.fullmatch(name):
            return True
        # Windows ignores trailing dots and spaces and treats ':' as a stream separator, so compare the base name.
        folded.append(name.split(":", 1)[0].rstrip(". ").casefold())
    for name in folded:
        dashed = name.replace(" ", "-")
        if (name in PROTECTED_COMPONENTS or name in PROTECTED_FILES or name.startswith(PROTECTED_PREFIXES)
                or any(dashed == prefix or dashed.startswith(prefix + "-") for prefix in BROWSER_PREFIXES)):
            return True
    for sequence in PROTECTED_SEQUENCES:
        size = len(sequence)
        if any(tuple(folded[index:index + size]) == sequence for index in range(len(folded) - size + 1)):
            return True
    # A selected root at or below an NTDS folder is refused; inside one, files of a directory-database type are
    # protected at any depth (dsadata.bak/, old/).
    below = next((index + 2 for index in range(len(folded) - 1) if tuple(folded[index:index + 2]) in NTDS_FOLDERS),
                 None)
    if below is not None and (selected_root or (below < len(folded)
                                                and PurePosixPath(folded[-1]).suffix in NTDS_SUFFIXES)):
        return True
    return bool(folded) and PurePosixPath(folded[-1]).suffix in PROTECTED_SUFFIXES


def protected(rel, *, root=None):
    """True if a path relative to the selected root names private data.

    With ``root``, the root's own components count too, so a name pair such as
    Library/Messages is found when the selection is the Library folder itself.
    """
    rel = os.fspath(rel)
    if not isinstance(rel, str):
        raise TypeError("protected needs a text path")
    names = _SEPARATORS.split(rel)
    if root is not None:
        prefix = _root_names(root)
        if prefix is None:
            return True
        names = prefix + names
    return _matches(names)


def protected_root(abs_path):
    """True if an owner-selected source or restore target must be refused: a system root, a protected
    name anywhere in its absolute path, or a domain controller's NTDS folder (Windows/NTDS, WINNT/NTDS)
    or anything below one.

    Only the harmless temporary prefixes in TEMPORARY_PREFIXES and /run/user/<uid> are skipped before
    matching; anything that is not a plain absolute path is refused. Generic names match too broadly
    (a clone under ~/git, a folder named vault), so backup destinations and PatchCairn's own work folder
    are checked with is_system_root instead.
    """
    names = _root_names(abs_path)
    return names is None or is_system_root(abs_path) or _matches(names, selected_root=True)
