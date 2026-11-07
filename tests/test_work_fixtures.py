"""Fictional checks of tests/work_fixtures.remove_tree, the one remover of the tests' fixture folders below work/."""
from __future__ import annotations

import os
from pathlib import Path
import stat
import sys
import unittest
import uuid

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parent))
from work_fixtures import ROOT, remove_tree  # noqa: E402


class RemoveTreeTests(unittest.TestCase):
    def test_a_link_inside_is_not_followed_a_read_only_file_goes_and_a_missing_folder_raises(self):
        base = ROOT / "work" / "test-fixtures" / ("remover-" + uuid.uuid4().hex)
        (base / "outside").mkdir(parents=True)
        self.addCleanup(remove_tree, base)
        kept = base / "outside" / "kept.txt"
        kept.write_bytes(b"fictional file the link leads to")
        tree = base / "tree"
        (tree / "inner").mkdir(parents=True)
        read_only = tree / "inner" / "read-only.txt"
        read_only.write_bytes(b"fictional read-only file")
        os.chmod(read_only, stat.S_IREAD)
        link = tree / "link"
        if os.name == "nt":
            import _winapi
            _winapi.CreateJunction(str(base / "outside"), str(link))  # a junction needs no symbolic-link privilege
        else:
            link.symlink_to(base / "outside", target_is_directory=True)
        remove_tree(tree)
        self.assertFalse(os.path.lexists(tree))
        self.assertEqual(kept.read_bytes(), b"fictional file the link leads to")
        with self.assertRaises(FileNotFoundError):
            remove_tree(tree)


if __name__ == "__main__":
    unittest.main()
