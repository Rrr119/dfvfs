#!/usr/bin/env python3
"""Tests for the LUKS2 path specification implementation."""

import unittest

from dfvfs.path import luks2_path_spec

from tests.path import test_lib


class LUKS2PathSpecTest(test_lib.PathSpecTestCase):
    """Tests the LUKS2 path specification implementation."""

    def testInitialize(self):
        """Tests the path specification initialization."""
        path_spec = luks2_path_spec.LUKS2PathSpec(parent=self._path_spec)

        self.assertIsNotNone(path_spec)

        with self.assertRaises(ValueError):
            luks2_path_spec.LUKS2PathSpec(parent=None)

        with self.assertRaises(ValueError):
            luks2_path_spec.LUKS2PathSpec(parent=self._path_spec, bogus="BOGUS")

    def testComparable(self):
        """Tests the path specification comparable property."""
        path_spec = luks2_path_spec.LUKS2PathSpec(
            keyfile="/test/keyfile", parent=self._path_spec, password="password"
        )

        self.assertIsNotNone(path_spec)

        expected_comparable = "\n".join(
            [
                "type: TEST",
                "type: LUKS2, password: password, keyfile: /test/keyfile",
                "",
            ]
        )

        self.assertEqual(path_spec.comparable, expected_comparable)


if __name__ == "__main__":
    unittest.main()
