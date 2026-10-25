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
        neighbours =("etc/NetworkManager/NetworkManager.conf", "etc/NetworkManager/dispatcher.d/01-ifupdown",
                      "etc/ppp/options", "etc/krb5.conf", "etc/ipsec.conf", "var/db/locate.database",
                      "src/wpa_supplicant/main.c", "hostap/wpa_supplicant/README",
                      "ProgramData/Microsoft/Windows/Start Menu/x.lnk", "Windows/System32/Microsoft/Windows/x.dll",
                      "Documents/Microsoft/notes.docx")
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
                     "/var/tmp/pc", "/private/tmp/pc", "/private/var/folders/ab/xyz123/T/pc")

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
        self.assertEqual(profile("windows", "a", "b"), "C:" + "\\Users\\example\\a\\b")
        self.assertEqual(profile("posix", "a"), "/ho" + "me/example/a")
        self.assertEqual(profile("wsl-mnt"), "/mnt/c" + "/Users/example")
        self.assertEqual(profile("posix").replace("/example", "//example"), "/ho" + "me//example")

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
