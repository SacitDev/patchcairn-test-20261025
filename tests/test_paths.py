"""pc_paths: the relative-path grammar, portable names, collision keys, protected names and system roots.

Run from the repository root: python3 -I -S -B -m unittest discover -s tests -p "test_paths.py"
Every case is text only; nothing on the host is opened or listed.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import pc_paths  # noqa: E402
from pc_paths import PathRefusal  # noqa: E402

FIXTURE = json.loads((ROOT / "tests" / "fixtures" / "path-conformance.json").read_text(encoding="utf-8"))


def case_path(case):
    if "path" in case:
        return case["path"]
    text, count = case["repeat"]
    return case.get("prefix", "") + text * count + case.get("suffix", "")


# Profile folders of the fictional user "example", in each spelling a caller may pass. They are put
# together at run time so the source never holds a literal user-profile path.
_PROFILE_ROOTS = {"windows": ("C:\\" + "Users", "\\"), "windows-slash": ("C:/" + "Users", "/"),
                  "posix": ("/" + "home", "/"), "macos": ("/" + "Users", "/"), "git-bash": ("/c/" + "Users", "/"),
                  "wsl-mnt": ("/mnt/c/" + "Users", "/"), "wsl-unc-home": ("\\\\wsl$\\Ubuntu\\" + "home", "\\"),
                  "wsl-unc-drive": ("\\\\wsl$\\Ubuntu\\mnt\\c\\" + "Users", "\\")}


def profile(platform, *parts):
    """The fictional user's profile folder on ``platform``, followed by ``parts``."""
    root, separator = _PROFILE_ROOTS[platform]
    return separator.join((root, "example") + parts)


class ConformanceFixtureTests(unittest.TestCase):
    def test_fixture_limits_match_the_module(self):
        self.assertEqual(FIXTURE["limits"], {"max_path_units": pc_paths.MAX_PATH_UNITS, "max_parts": pc_paths.MAX_PARTS,
                                             "max_name_bytes": pc_paths.MAX_NAME_BYTES})

    def test_relative_path_conformance(self):
        for case in FIXTURE["relative"]:
            path = case_path(case)
            with self.subTest(why=case["why"], path=path[:40]):
                if case["valid"]:
                    self.assertIs(pc_paths.relative(path), path)
                else:
                    with self.assertRaises(PathRefusal) as caught:
                        pc_paths.relative(path)
                    self.assertEqual(caught.exception.code, case["code"])

    def test_portable_agrees_with_the_grammar(self):
        for case in FIXTURE["relative"]:
            path = case_path(case)
            with self.subTest(why=case["why"], path=path[:40]):
                self.assertEqual(pc_paths.portable(path), case["valid"])

    def test_casefold_pairs(self):
        for pair in FIXTURE["casefold_pairs"]:
            with self.subTest(pair=pair):
                same = pc_paths.casefold_key(pair["a"]) == pc_paths.casefold_key(pair["b"])
                self.assertEqual(same, pair["same"])

    def test_fixture_covers_the_required_cases(self):
        paths = {case_path(case) for case in FIXTURE["relative"]}
        for required in ("COM0", "LPT0", "COM\u00b9", "foo.", "foo ", "a:b", "PROGRA~1/DOCUME~1.TXT", "caf\u00e9",
                         "cafe\u0301", "..", "a//b", "../escape"):
            self.assertIn(required, paths)
        self.assertIn(True, [pair["same"] and pair["a"] == "caf\u00e9" for pair in FIXTURE["casefold_pairs"]])


class GrammarTests(unittest.TestCase):
    def test_path_refusal_has_the_refusal_shape(self):
        # It cannot subclass pc_records.Refusal (this layer imports no product module), so it keeps the same
        # shape: a ValueError with a categorical code and the same constructor.
        self.assertTrue(issubclass(PathRefusal, ValueError))
        self.assertEqual((PathRefusal("bare").code, str(PathRefusal("bare"))), ("bare", "bare"))
        self.assertEqual(str(PathRefusal("code-x", "detail")), "detail")
        tree = ast.parse((ROOT / "scripts" / "pc_paths.py").read_text(encoding="utf-8"))
        bases = [node.bases for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "PathRefusal"][0]
        self.assertEqual([ast.unparse(base) for base in bases], ["ValueError"])

    def test_relative_refuses_values_that_are_not_text(self):
        for value in (None, b"a", 1, PurePosixPath("a"), ["a"]):
            with self.subTest(value=repr(value)):
                with self.assertRaises(PathRefusal) as caught:
                    pc_paths.relative(value)
                self.assertEqual(caught.exception.code, "invalid-relative-path")
                self.assertIsInstance(caught.exception, ValueError)

    def test_paths_that_cannot_be_stored_portably(self):
        for path in ("a:b", "nul.txt", "x ", "x.", "a" * 256, "a" * 201, "", ".", "..", "a\\b", "/a", "a//b", None, b"a",
                     "b" * 60 + "/" + "a" * 150, "a/" * 64 + "a", "docs/con.txt"):
            with self.subTest(path=repr(path)[:30]):
                self.assertFalse(pc_paths.portable(path))
        for path in ("a" * 200, "report.docx", ".bashrc", "PROGRA~1", "a/b", "docs/2026/report.docx", "a/" * 63 + "a"):
            self.assertTrue(pc_paths.portable(path))

    def test_length_has_its_own_refusal_code(self):
        for path in ("a" * 201, "b" * 60 + "/" + "a" * 150, "a/" * 64 + "a"):
            with self.subTest(path=path[:20]):
                with self.assertRaises(PathRefusal) as caught:
                    pc_paths.relative(path)
                self.assertEqual(caught.exception.code, "path-too-long")

    def test_display_escapes_what_could_hide_or_reorder_a_name(self):
        rlo, zwsp, bom, nel, line, surrogate = chr(0x202E), chr(0x200B), chr(0xFEFF), chr(0x85), chr(0x2028), chr(0xDCFF)
        self.assertEqual(pc_paths.display("invoice" + rlo + "fdp.exe"), "invoice\\u202efdp.exe")
        self.assertEqual(pc_paths.display("a" + zwsp + bom + nel + line + "\t\n" + surrogate),
                         "a\\u200b\\ufeff\\u0085\\u2028\\u0009\\u000a\\udcff")
        self.assertEqual(pc_paths.display("back\\slash"), "back\\u005cslash")
        self.assertEqual(pc_paths.display("caf" + chr(0xE9) + " " + chr(0x65E5) + chr(0x1F600)), "caf" + chr(0xE9) + " "
                         + chr(0x65E5) + chr(0x1F600))
        self.assertEqual(pc_paths.display(chr(0xE0001)), "\\U000e0001")
        with self.assertRaises(TypeError):
            pc_paths.display(b"a")

    def test_names_are_not_normalised(self):
        self.assertEqual(pc_paths.relative("cafe\u0301"), "cafe\u0301")
        self.assertNotEqual(pc_paths.relative("cafe\u0301"), pc_paths.relative("caf\u00e9"))

    def test_casefold_key_requires_text(self):
        with self.assertRaises(TypeError):
            pc_paths.casefold_key(b"a")


class ProtectedNameTests(unittest.TestCase):
    def test_todays_names_stay_protected(self):
        for rel in (".ssh/id_ed25519.pub", "x/.gnupg/pubring.kbx", "AppData/Local/x", "Keychains/login", "vault/a.txt",
                    "chrome/Default/Preferences", "google-chrome-beta/x", "Microsoft Edge/User Data", "Brave-Browser/x",
                    "notes/.env", "notes/.env.local", "a/id_rsa", "Cookies", "Login Data", "logins.json",
                    "backup/server.pem", "certs/a.pfx", "db.kdbx", ".claude/x", "git/config", "sessions/a.json",
                    "x/known_hosts", "x/.git-credentials", "y/state.vscdb"):
            with self.subTest(rel=rel):
                self.assertTrue(pc_paths.protected(rel))

    def test_added_names_are_protected(self):
        for rel in (".password-store/mail.gpg", "keys/server.ppk", "export/secret.gpg", "keys/public.asc", ".pgpass",
                    "home/Library/Messages/chat.db", "Library/messages"):
            with self.subTest(rel=rel):
                self.assertTrue(pc_paths.protected(rel))

    def test_system_names_inside_a_root_are_ordinary_folders(self):
        for rel in ("dev/notes.txt", "etc/config.yaml", "windows/runner/main.cpp", "boot/loader.cfg", "proc/a",
                    "sys/b", "System32/readme.txt", "Program Files/x", "programdata/x", "usr/share/doc", "Library/Fonts/a.ttf",
                    "Documents/report.docx", "photos/2026/img.jpg", "src/app/main.py", "messages/inbox.txt",
                    "etc/hosts", "share/trash-talk.txt", "config/system32.txt"):
            with self.subTest(rel=rel):
                self.assertFalse(pc_paths.protected(rel))

    def test_credential_stores_of_a_copied_system_are_protected(self):
        for rel in ("etc/shadow", "etc/gshadow", "etc/shadow-", "etc/gshadow-", "etc/ssh/ssh_host_ed25519_key",
                    "Windows/System32/config/SAM", "Windows/System32/config/SECURITY", "WINDOWS/SYSTEM32/CONFIG"):
            with self.subTest(rel=rel):
                self.assertTrue(pc_paths.protected(rel))
                self.assertTrue(pc_paths.protected(rel, root="/media/example/OLDDISK"))
        self.assertTrue(pc_paths.protected("ssh/sshd_config", root="/media/example/OLDDISK/etc"))

    def test_saved_network_keys_and_account_stores_are_protected(self):
        stores = ("etc/NetworkManager/system-connections/home.nmconnection", "etc/wpa_supplicant/wpa_supplicant.conf",
                  "etc/wpa_supplicant/wpa_supplicant-wlan0.conf", "boot/wpa_supplicant.conf", "etc/krb5.keytab",
                  "srv/http.keytab", "etc/ppp/chap-secrets", "etc/ppp/pap-secrets", "etc/ipsec.secrets",
                  "var/db/dslocal/nodes/Default/users/example.plist", "private/var/db/dslocal",
                  "Windows/System32/Microsoft/Protect/S-1-5-18/User/key",
                  "ProgramData/Microsoft/Crypto/RSA/MachineKeys/abc")
        for rel in stores:
            with self.subTest(rel=rel):
                self.assertTrue(pc_paths.protected(rel))
                self.assertTrue(pc_paths.protected(rel, root="/media/example/OLDDISK"))
        neighbours = ("etc/NetworkManager/NetworkManager.conf", "etc/NetworkManager/dispatcher.d/01-ifupdown",
                      "etc/ppp/options", "etc/krb5.conf", "etc/ipsec.conf", "var/db/locate.database",
                      "src/wpa_supplicant/main.c", "hostap/wpa_supplicant/README",
                      "ProgramData/Microsoft/Windows/Start Menu/x.lnk", "Windows/System32/Microsoft/Windows/x.dll",
                      "Documents/Microsoft/notes.docx")
        for rel in neighbours:
            with self.subTest(rel=rel):
                self.assertFalse(pc_paths.protected(rel))

    def test_more_system_credential_stores_are_protected(self):
        # Stores on a copied system disk: VPN and Wi-Fi keys, BSD and macOS password hashes, Samba's password
        # databases in every layout, SSSD's and winbind's login caches, earlier Linux password hashes, the Windows
        # account database (its old copies in Windows\repair and a domain controller's NTDS folder). Several rows
        # match only one rule.
        stores = ("etc/wireguard/wg0.conf", "var/lib/iwd/home.psk", "etc/master.passwd", "private/etc/master.passwd",
                  "etc/spwd.db", "etc/samba/smbpasswd", "etc/samba/private/smbpasswd",  # gitleaks:allow
                  # Samba: Debian and RHEL, a source build, FreeBSD, TrueNAS, other prefixes, Samba 3 layouts, a
                  # samba-tool backup, and winbind's offline-logon cache.
                  "var/lib/samba/private/secrets.tdb", "var/lib/samba/private/smbpasswd",  # gitleaks:allow
                  "var/lib/samba/private/privilege.ldb", "usr/local/samba/private/privilege.ldb",
                  "var/db/samba4/private/privilege.ldb", "var/db/samba4/private/secrets.tdb",
                  "var/db/system/samba4/private/smbpasswd", "var/db/system/samba4/private/netlogon_creds_cli.tdb",
                  "mydisk/samba/private/smbpasswd",
                  "samba-backup/private/smbpasswd", "var/lib/samba/secrets.tdb", "var/lib/samba/passdb.tdb",
                  "etc/samba/secrets.tdb", "samba-backup/private/sam.ldb", "samba-backup/private/secrets.ldb",
                  "samba-backup/private/sam.ldb.d/DC=EXAMPLE,DC=COM.ldb", "var/cache/samba/winbindd_cache.tdb",
                  "var/lib/samba/winbindd_cache.tdb", "var/lib/sss/db/cache_example.com.ldb",
                  "var/db/sss/db/cache_example.com.ldb", "etc/security/opasswd",
                  # Windows: the repair copies (also in RegBack, also on Windows 2000) and the NTDS engine files.
                  "Windows/repair/SAM", "WINDOWS/Repair/SECURITY", "Windows/repair/system", "Windows/repair/software",
                  "WINNT/repair/sam", "WINNT/repair/security", "WINNT/repair/system", "WINNT/repair/software",
                  "Windows/repair/RegBack/SAM", "WINNT/repair/RegBack/system", "Windows/NTDS/ntds.dit",
                  "Windows/NTDS/edb.log", "Windows/NTDS/edb0001A.log", "Windows/NTDS/edb.chk",
                  "Windows/NTDS/edbres00001.jrs", "Windows/NTDS/ntds.jfm", "Windows/NTDS/temp.edb",
                  "WINNT/NTDS/edb.log", "NTDS-data/ntds.dit",
                  # Renamed database copies kept after an offline defragmentation, NTDS subfolders, and AD LDS.
                  "Windows/NTDS/ntds.dit.old", "Windows/NTDS/ntds_old.dit", "Windows/NTDS/ntds.dit.bak",
                  "Windows/NTDS/ntds.bak", "Windows/NTDS/ntds.old",
                  "backup/ntds.dit.bak", "WINNT/NTDS/dsadata.bak/edb.log", "Windows/NTDS/old/edb00002.log",
                  "Program Files/Microsoft ADAM/instance1/data/adamntds.dit",
                  # IPsec: ipsec.d (Libreswan, older strongSwan) and swanctl (strongSwan; Fedora under strongswan/).
                  "etc/ipsec.d/private/key.der", "etc/strongswan/ipsec.d/private/key.der", "etc/ipsec.d/home.secrets",
                  "etc/ipsec.d/key3.db", "etc/ipsec.d/nsspassword", "etc/swanctl/private/key.der",
                  "etc/swanctl/rsa/key.der", "etc/swanctl/ecdsa/key.der", "etc/swanctl/bliss/key.der",
                  "etc/swanctl/pkcs8/key.der", "etc/strongswan/swanctl/pkcs12/vpn", "etc/swanctl/swanctl.conf",
                  "etc/strongswan/swanctl/swanctl.conf", "etc/swanctl/conf.d/vpn.conf", "backup/swanctl.conf",
                  "Program Files/WireGuard/Data/Configurations/wg0.conf.dpapi")
        for rel in stores:
            with self.subTest(rel=rel):
                self.assertTrue(pc_paths.protected(rel))
                self.assertTrue(pc_paths.protected(rel, root="/Volumes/OLDDISK"))
        self.assertTrue(pc_paths.protected("wg0.conf", root="/Volumes/OLDDISK/etc/wireguard"))
        # A person's own folders named after these systems stay readable.
        neighbours = ("etc/samba/smb.conf", "usr/bin/smbpasswd", "srv/samba/private/report.docx",
                      "Shares/Samba/Private/taxes.pdf", "var/lib/samba/usershares/data",
                      "var/cache/samba/printing/queue.tdb", "src/wireguard/main.c",
                      "Program Files/WireGuard/wireguard.exe", "var/lib/iwd-notes.txt", "etc/ipsec.d/policies/clear",
                      "etc/strongswan.conf", "etc/strongswan.d/charon.conf", "etc/swanctl/x509/peer.der",
                      "etc/swanctl/pubkey/peer.der", "etc/security/limits.conf", "Windows/Logs/CBS/CBS.log",
                      "Windows/repair/setup.log", "Documents/IT/Windows/Repair/guide.md",
                      "Documents/IT/Windows/Repair/regback.md", "clients/windows/repair/invoice.pdf",
                      "docs/repair/windows.md", "Documents/IT/Windows/NTDS/notes.md",
                      "Documents/IT/Windows/NTDS/old/notes.md", "clients/windows/ntds/invoice.pdf",
                      "backup/ntds-notes.txt", "src/samba4/README.md")
        for rel in neighbours:
            with self.subTest(rel=rel):
                self.assertFalse(pc_paths.protected(rel))

    def test_more_credential_files_are_protected(self):
        # Registry tokens (Cargo, Terraform, OpenTofu), the Vault token, a CI runner's .secrets file, the sops age key
        # folder on Linux and macOS and keys.txt under any configuration folder (XDG_CONFIG_HOME, a dotfiles copy,
        # Windows' Roaming), wallets and their copies, Ethereum key folders (~/.ethereum, ~/Library/Ethereum) and key
        # files anywhere, test-network keystores included.
        files = (".cargo/credentials.toml", ".cargo/credentials", ".terraform.d/credentials.tfrc.json", ".terraformrc",
                 "old-pc/terraform.rc", ".tofurc", ".config/opentofu/tofurc", "old-pc/tofu.rc", "proj/ci.tfrc",
                 ".vault-token", "projects/app/.secrets", ".config/sops/age/keys.txt", ".config/sops/age/keys.txt.bak",
                 ".config/sops/age/old-keys.txt", "Library/Application Support/sops/age/keys.txt",
                 "dot_config/sops/age/keys.txt", "custom-xdg/sops/age/keys.txt", "Roaming/sops/age/keys.txt",
                 "wallet.dat", "Bitcoin/wallet.dat", "old/coins/WALLET.DAT", "Bitcoin/wallet.dat.bak",
                 ".ethereum/keystore/key.json", "Library/Ethereum/keystore/key.json",
                 ".ethereum/sepolia/keystore/UTC--2026-x", "Library/Ethereum/holesky/keystore/UTC--2026-x",
                 "backup/keys/UTC--2026-10-25T01-02-03.0Z--ab12")
        for rel in files:
            with self.subTest(rel=rel):
                self.assertTrue(pc_paths.protected(rel))
                self.assertTrue(pc_paths.protected(rel, root=profile("macos")))
        self.assertTrue(pc_paths.protected("sops/age/keys.txt", root="D:\\OldPC\\Roaming"))
        neighbours = (".cargo/config.toml", ".cargo/registry/index/x", ".terraform.d/plugins/x", "docs/terraform.md",
                      "projects/infra/main.tf", "projects/infra/.terraform.lock.hcl", "docs/opentofu.md",
                      "projects/app/.sops.yaml", "projects/sops/age/keysource.go", ".config/sops/config.yaml",
                      "notes/wallet.txt", ".ethereum/geth/chaindata/x", "notes/utc-times.txt")
        for rel in neighbours:
            with self.subTest(rel=rel):
                self.assertFalse(pc_paths.protected(rel))

    def test_deleted_files_and_restore_points_inside_a_root_are_protected(self):
        for rel in ("$RECYCLE.BIN/S-1-5-21/x.txt", "System Volume Information/tracking.log", ".Trash/old.pdf",
                    ".Trashes/501/x", ".Trash-1000/files/x", "home/.local/share/Trash/files/x"):
            with self.subTest(rel=rel):
                self.assertTrue(pc_paths.protected(rel))

    def test_windows_spellings_cannot_hide_a_protected_name(self):
        for rel in (".SSH/config", "AppData./x", "AppData  /x", "appdata::$INDEX_ALLOCATION/x", "x.PEM", "x.pem.",
                    "keys\\a.key", ".ENV.production", "SSH~1/config", "GNUPG~1/pubring.kbx", "x/SSH~1/ID_ED2~1"):
            with self.subTest(rel=rel):
                self.assertTrue(pc_paths.protected(rel))

    def test_ignorable_characters_cannot_hide_a_protected_name(self):
        # Mac OS Extended ignores these code points when it compares names.
        for char in (0x200C, 0x200D, 0x200E, 0x202A, 0x202E, 0x206A, 0xFEFF):
            with self.subTest(char=hex(char)):
                self.assertTrue(pc_paths.protected("." + chr(char) + "ssh/config"))
                self.assertTrue(pc_paths.protected(".s" + chr(char) + "sh"))
                self.assertTrue(pc_paths.protected_root("/Volumes/Old" + profile("macos", ".ss" + chr(char) + "h")))

    def test_name_pairs_are_found_across_the_root_boundary(self):
        self.assertTrue(pc_paths.protected("Messages/chat.db", root=profile("macos", "Library")))
        self.assertTrue(pc_paths.protected("Messages/chat.db", root=PurePosixPath(profile("macos", "Library"))))
        self.assertFalse(pc_paths.protected("Messages/chat.db"))
        self.assertFalse(pc_paths.protected("Messages/chat.db", root=profile("macos", "Documents")))
        self.assertFalse(pc_paths.protected("Documents/a.txt", root="/tmp/Library"))
        self.assertFalse(pc_paths.protected("", root=profile("windows", "Documents")))

    def test_invalid_root_fails_closed(self):
        for root in ("relative/path", "", "C:x", "\\\\?\\" + profile("windows"), profile("posix").encode()):
            with self.subTest(root=root):
                self.assertTrue(pc_paths.protected("Documents/a.txt", root=root))

    def test_protected_needs_a_text_path(self):
        for value in (b"a", None, 1):
            with self.subTest(value=repr(value)), self.assertRaises(TypeError):
                pc_paths.protected(value)
        self.assertTrue(pc_paths.protected(PurePosixPath(".ssh/config")))


class RootRefusalTests(unittest.TestCase):
    def refused(self, *paths):
        for path in paths:
            with self.subTest(path=path):
                self.assertTrue(pc_paths.protected_root(path))

    def allowed(self, *paths):
        for path in paths:
            with self.subTest(path=path):
                self.assertFalse(pc_paths.is_system_root(path))
                self.assertFalse(pc_paths.protected_root(path))

    def test_root_inside_browser_profile_refused(self):
        self.refused(profile("windows", "AppData", "Local", "Google", "Chrome", "User Data"),
                     profile("windows-slash", "AppData", "Roaming", "Mozilla", "Firefox", "Profiles", "x.default"),
                     profile("posix", ".config", "google-chrome", "Default"),
                     profile("posix", ".mozilla", "firefox", "x.default-release"),
                     profile("macos", "Library", "Application Support", "Google", "Chrome", "Default"),
                     profile("macos", "Library", "Safari"),
                     profile("posix", ".config", "BraveSoftware", "Brave-Browser", "Default"),
                     "/tmp/profiles/chromium/Default")

    def test_root_inside_dot_ssh_refused(self):
        self.refused(profile("posix", ".ssh"), profile("macos", ".ssh", "keys"), profile("windows", ".ssh"),
                     "/tmp/copy/.ssh", "/dev/shm/x/.ssh", profile("posix", ".gnupg"), profile("posix", ".password-store"),
                     profile("macos", "Library", "Messages"), profile("macos", "Library", "Messages", "Attachments"))

    def test_dev_shm_root_allowed(self):
        self.allowed("/dev/shm/patchcairn-test/root", "/dev/shm", "/run/user/1000/patchcairn/root", "/tmp/pc/root",
                     "/var/tmp/pc", "/private/tmp/pc", "/private/var/tmp/pc", "/private/var/folders/ab/xyz123/T/pc")

    def same_answers(self, short, resolved, rests):
        # macOS resolves /var/... to /private/var/..., so an unresolved root must get the answers of the real path.
        for rest in rests:
            with self.subTest(short=short, rest=rest):
                self.assertEqual(pc_paths.is_system_root(short + rest), pc_paths.is_system_root(resolved + rest))
                self.assertEqual(pc_paths.protected_root(short + rest), pc_paths.protected_root(resolved + rest))
                self.assertEqual(pc_paths.protected("Messages/x", root=short + rest + "/Library"),
                                 pc_paths.protected("Messages/x", root=resolved + rest + "/Library"))

    def test_var_folders_is_treated_like_private_var_folders(self):
        rests = ("", "/ab/xyz123/T", "/ab/xyz123/T/pc/root", "/ab/xyz123/T/x/.ssh", "/ab/xyz123/C/Library/Messages")
        self.same_answers("/var/folders", "/private/var/folders", rests)
        self.allowed("/var/folders/ab/xyz123/T/pc", "/var/folders/ab/xyz123/T/pc/root")
        self.refused("/var/folders/ab/xyz123/T/x/.ssh")
        for path in ("/var/foldersx/a", "/var/folder/a", "/var/db/x"):
            with self.subTest(path=path):
                self.assertTrue(pc_paths.is_system_root(path))

    def test_var_tmp_is_treated_like_private_var_tmp(self):
        self.same_answers("/var/tmp", "/private/var/tmp", ("", "/pc", "/pc/root", "/x/.ssh", "/copy/Library/Messages"))
        self.allowed("/private/var/tmp/pc", "/private/var/tmp/pc/root")
        self.refused("/private/var/tmp/x/.ssh")
        for path in ("/private/var/tmpx/a", "/private/var/db/x"):
            with self.subTest(path=path):
                self.assertTrue(pc_paths.is_system_root(path))

    def test_mnt_and_mnt_wsl_are_system_roots(self):
        # On WSL /mnt holds every Windows drive, so a selected /mnt would reach c/Windows without a system-root check.
        # A path alone cannot tell WSL from another Linux, so these are refused on every system.
        for path in ("/mnt", "/mnt/", "/mnt/wsl", "/mnt/wsl/", "/MNT", "\\\\wsl$\\Ubuntu\\mnt",
                     "\\\\wsl.localhost\\Ubuntu\\mnt\\wsl"):
            with self.subTest(path=path):
                self.assertTrue(pc_paths.is_system_root(path))
                self.assertTrue(pc_paths.protected_root(path))
        self.allowed(profile("wsl-mnt", "Documents"), profile("wsl-unc-drive", "Documents"), "/mnt/data/archive",
                     "/mnt/usb", "/mnt/wsl/shared", "/mnt/wslx", "/mnt/wslgx/a")

    def test_ntds_folder_is_refused_as_a_root(self):
        # A domain controller's NTDS folder holds every domain account's password hashes: selecting it, or a folder
        # below it, is refused; its neighbours and a person's folder merely named NTDS stay selectable.
        self.refused("/mnt/old/Windows/NTDS", "/mnt/old/WINNT/NTDS", "/mnt/old/windows/ntds/",
                     "D:\\OldDC\\Windows\\NTDS", "/Volumes/OLDDC/Windows/NTDS/dsadata.bak")
        self.allowed("/mnt/old/Windows", "/mnt/old/Documents/IT/NTDS", "D:\\OldDC\\NTDS-notes")
        self.assertFalse(pc_paths.protected("notes.md", root="/mnt/old/Documents/IT/NTDS"))

    def test_mnt_wslg_and_everything_below_it_are_system_roots(self):
        # WSLg's runtime folder holds sockets, logs and a view of the distribution, never a person's files.
        for path in ("/mnt/wslg", "/mnt/wslg/", "/mnt/wslg/distro", "/mnt/wslg/distro/etc", "/mnt/wslg/runtime-dir",
                     "/MNT/WSLG/x", "\\\\wsl$\\Ubuntu\\mnt\\wslg\\distro"):
            with self.subTest(path=path):
                self.assertTrue(pc_paths.is_system_root(path))
                self.assertTrue(pc_paths.protected_root(path))

    def test_short_name_first_component_is_a_system_root(self):
        # On a Windows host a rooted 8.3 alias opens a system folder (/PROGRA~1 is C:\Program Files), and backup
        # destinations are checked with is_system_root alone.
        for path in ("/PROGRA~1/x", "/PROGRA~2", "/PROGRA~3/x", "/WINDOW~1/System32", "/progra~1/App/", "/SYSTEM~1",
                     "/$RECYC~1.BIN/S-1-5", "/PROGRA~1./x", "/PROGRA~1::$INDEX_ALLOCATION/x", "C:\\PROGRA~1\\App",
                     "D:/WINDOW~1/System32", "/c/PROGRA~1/App", "/mnt/c/WINDOW~1/System32",
                     "\\\\wsl$\\Ubuntu\\mnt\\c\\PROGRA~2\\x", "\\\\server\\share\\WINDOW~1"):
            with self.subTest(path=path):
                self.assertTrue(pc_paths.is_system_root(path))
                self.assertTrue(pc_paths.protected_root(path))
        self.allowed("/backup~old/x", "/srv/files~2026/x")

    def test_removable_drives_under_run_media_are_allowed(self):
        self.allowed("/run/media/example/USB/photos", "/run/media/example/USB")
        for path in ("/run/media/example", "/run/media", "/run/mediax/example/USB/x"):
            with self.subTest(path=path):
                self.assertTrue(pc_paths.is_system_root(path))
        self.refused("/run/media/example/USB/.ssh")

    def test_temporary_prefixes_are_stripped_only_exactly(self):
        for path in ("/dev/shmx/a", "/dev/sda", "/run/user/abc/x", "/run/user", "/var/tmpx/a", "/private/var/db",
                     "/private", "/private/etc/hosts"):
            with self.subTest(path=path):
                self.assertTrue(pc_paths.is_system_root(path))
                self.assertTrue(pc_paths.protected_root(path))

    def test_system_roots_refused(self):
        windows = ("C:\\", "D:/", "C:\\Windows", "c:\\windows\\system32\\drivers", "C:\\Program Files\\App",
                   "C:/Program Files (x86)", "C:/Program Files (Arm)/x", "C:\\ProgramData\\x",
                   "D:\\System Volume Information", "E:\\$Recycle.Bin\\S-1-5", "C:\\Recovery\\WindowsRE",
                   "C:\\Windows.old\\Users", "\\\\server\\share", "\\\\server\\c$\\Windows",
                   "\\\\localhost\\ADMIN$\\System32\\config", "\\\\localhost\\ADMIN$\\System32\\drivers",
                   "\\\\server\\C$" + profile("windows", "Documents")[2:], "\\\\wsl.localhost\\Ubuntu\\etc",
                   "\\\\wsl$\\Ubuntu\\usr\\lib",
                   # Windows drives reached through a WSL distribution's share are checked as Windows drives.
                   "\\\\wsl$\\Ubuntu\\mnt\\c\\Windows\\System32", "\\\\wsl.localhost\\Ubuntu\\mnt\\c",
                   "\\\\wsl$\\Ubuntu\\mnt\\c\\Program Files", "\\\\wsl$\\Ubuntu\\mnt\\c", "\\\\wsl$\\Ubuntu",
                   "\\\\wsl$\\Ubuntu\\c\\Windows", "\\\\wsl.localhost\\Debian\\mnt\\D\\ProgramData\\x")
        posix = ("/", "/usr/local/x", "/var/lib", "/opt/app", "/etc", "/bin", "/sbin", "/lib", "/lib64", "/libx32",
                 "/boot/efi", "/efi/EFI", "/snap/core22", "/nix/store/x", "/dev/sda", "/proc/1", "/sys/kernel",
                 "/run/secrets", "/run/credentials/x", "/System/Library", "/Library/Keychains", "/Applications/App.app",
                 "/USR/bin", "/mnt/c", "/mnt/c/Windows/System32", "/mnt/D/Program Files/x", "/c/Windows/System32",
                 "/d", "/Windows/System32", "/Program Files/App", "/Windows./System32",
                 "/Windows::$INDEX_ALLOCATION/System32", "/ProgramData /x")
        # Linux and macOS read a leading '//' as '/', so these are the real system folders.
        doubled = ("//usr/local/bin", "//etc/ssh/sshd_config.d", "//boot/efi/EFI", "//var/lib/docker",
                   "//Library/Keychains/x", "//proc/self/fd", "//tmp/.ssh/x", "//etc/ssl/private", "//var/lib/x/y",
                   "//server/share/", "/\\server\\share\\Windows", "\\/server/share/Windows")
        for path in windows + posix + doubled:
            with self.subTest(path=path):
                self.assertTrue(pc_paths.is_system_root(path))
                self.assertTrue(pc_paths.protected_root(path))

    def test_ordinary_roots_allowed(self):
        self.allowed(profile("windows", "Documents"), "D:\\Backups\\photos", profile("posix", "Documents"),
                     profile("macos", "Pictures"), profile("wsl-mnt", "Documents"), "/mnt/data/archive",
                     "/media/example/usb/photos", "/Volumes/USB/photos", "\\\\server\\share\\team\\docs",
                     profile("posix", "projects", "app", "windows"), profile("posix", "dev", "project"),
                     profile("posix", "etc"), profile("windows", "Windows"), "/srv/files", profile("posix", "Documents", ""),
                     "D:\\data\\", PurePosixPath(profile("posix", "docs")), PureWindowsPath(profile("windows-slash", "Music")),
                     profile("git-bash", "Documents"), profile("wsl-unc-home", "docs"), "/mnt/wsl/shared",
                     profile("wsl-unc-drive", "Documents"))

    def test_ambiguous_spellings_fail_closed(self):
        windows_users = profile("windows")[:-len("\\example")]
        for path in (profile("posix")[1:], "", "C:relative", "C:", "\\\\?\\" + profile("windows"), "\\\\.\\PhysicalDrive0",
                     "//?/C:/Users", "\\\\server", "C:\\Windows.", "C:\\Windows ", "C:\\Windows::$INDEX_ALLOCATION",
                     "C:\\PROGRA~1\\App", profile("windows", "APPDAT~1", "Local"), windows_users + "\\\\example",
                     windows_users + "\\nul\\x", profile("posix", "..", "..", "etc"), profile("posix").replace("/example", "//example"),
                     profile("posix").replace("/example", "/./example"), profile("posix") + "\x00x",
                     profile("posix").encode(), None, 7, PureWindowsPath("C:/Windows"), "/mnt/c/PROGRA~1/App",
                     profile("wsl-mnt", "APPDAT~1", "Local"), "/mnt/c/PROGRA~1/Common Files", "/mnt/c/PROGRA~3/Microsoft",
                     "/mnt/c/SYSTEM~1", "/mnt/c/Windows./x", profile("wsl-mnt")[:-len("/example")] + "/nul",
                     "/c/PROGRA~1/App", "\\\\server\\share\\PROGRA~1", profile("posix") + "\\x",
                     "\\\\wsl$\\Ubuntu\\mnt\\c\\PROGRA~1\\App", profile("wsl-unc-drive", "APPDAT~1"),
                     "\\\\wsl.localhost\\Ubuntu\\mnt\\c\\Windows.\\x", "\\\\wsl$\\Ubuntu\\home\\..\\etc"):
            with self.subTest(path=repr(path)):
                self.assertTrue(pc_paths.is_system_root(path))
                self.assertTrue(pc_paths.protected_root(path))

    def test_profile_helper_builds_each_spelling(self):
        # Written out apart from _PROFILE_ROOTS, so a mistyped root in any of the eight spellings fails here.
        expected = {"windows": ("C:" + "\\Users\\example", "\\"), "windows-slash": ("C:" + "/Users/example", "/"),
                    "posix": ("/ho" + "me/example", "/"), "macos": ("/" + "Users/example", "/"),
                    "git-bash": ("/c" + "/Users/example", "/"), "wsl-mnt": ("/mnt/c" + "/Users/example", "/"),
                    "wsl-unc-home": ("\\\\wsl$\\Ubuntu" + "\\home\\example", "\\"),
                    "wsl-unc-drive": ("\\\\wsl$\\Ubuntu\\mnt\\c" + "\\Users\\example", "\\")}
        self.assertEqual(set(expected), set(_PROFILE_ROOTS))
        for platform, (folder, separator) in expected.items():
            with self.subTest(platform=platform):
                self.assertEqual(profile(platform), folder)
                self.assertEqual(profile(platform).split(separator)[-1], "example")
                self.assertEqual(profile(platform, "x"), profile(platform) + separator + "x")
                self.assertEqual(profile(platform, "a", "b"), folder + separator + "a" + separator + "b")

    def test_generic_words_in_a_root_path_still_refuse_it(self):
        # A documented limit: generic names such as git, session or vault, and 8.3-looking names, match too broadly.
        self.refused(profile("posix", "git", "project"), profile("windows", "session", "x"),
                     profile("posix", "Documents", "vault"), profile("posix", "backup~1"))


class ModuleLayerTests(unittest.TestCase):
    def test_imports_standard_library_only(self):
        tree = ast.parse((ROOT / "scripts" / "pc_paths.py").read_text(encoding="utf-8"))
        imported = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        imported |= {node.module.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        self.assertLessEqual(imported, {"__future__", "os", "pathlib", "re", "unicodedata"})


if __name__ == "__main__":
    unittest.main()
