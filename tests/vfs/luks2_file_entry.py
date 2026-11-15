#!/usr/bin/env python3
"""Tests for the LUKS2 file entry implementation."""

import unittest

from dfvfs.lib import definitions
from dfvfs.path import factory as path_spec_factory
from dfvfs.resolver import context
from dfvfs.resolver import resolver
from dfvfs.vfs import luks2_file_entry
from dfvfs.vfs import luks2_file_system

from tests import test_lib as shared_test_lib


class LUKS2FileEntryTest(shared_test_lib.BaseTestCase):
    """Tests the LUKS2 file entry."""

    _PASSWORD = "luks2-TEST"

    def setUp(self):
        """Sets up the needed objects used throughout the test."""
        resolver.Resolver.key_chain.Empty()
        self._resolver_context = context.Context()

        test_path = self._GetTestFilePath(["luks2.raw"])
        self._SkipIfPathNotExists(test_path)

        test_os_path_spec = path_spec_factory.Factory.NewPathSpec(
            definitions.TYPE_INDICATOR_OS, location=test_path
        )
        self._luks2_path_spec = path_spec_factory.Factory.NewPathSpec(
            definitions.TYPE_INDICATOR_LUKS2, parent=test_os_path_spec
        )

        self._file_system = luks2_file_system.LUKS2FileSystem(
            self._resolver_context, self._luks2_path_spec
        )
        self._file_system.Open()

    def tearDown(self):
        """Cleans up the needed objects used throughout the test."""
        self._resolver_context.Empty()
        resolver.Resolver.key_chain.Empty()

    def testInitialize(self):
        """Tests the __init__ function."""
        file_entry = luks2_file_entry.LUKS2FileEntry(
            self._resolver_context, self._file_system, self._luks2_path_spec
        )
        self.assertIsNotNone(file_entry)

    def testSize(self):
        """Tests the size property."""
        file_entry = self._file_system.GetFileEntryByPathSpec(self._luks2_path_spec)
        self.assertIsNotNone(file_entry)
        self.assertEqual(file_entry.size, 15204352)

    def testIsLockedAndUnlock(self):
        """Tests the IsLocked and Unlock functions."""
        file_entry = self._file_system.GetFileEntryByPathSpec(self._luks2_path_spec)
        self.assertIsNotNone(file_entry)
        self.assertTrue(file_entry.IsLocked())

        resolver.Resolver.key_chain.SetCredential(
            self._luks2_path_spec, "password", self._PASSWORD
        )
        self.assertTrue(file_entry.Unlock())
        self.assertFalse(file_entry.IsLocked())

    def testSubFileEntries(self):
        """Tests the sub file entries property."""
        file_entry = self._file_system.GetFileEntryByPathSpec(self._luks2_path_spec)
        self.assertIsNotNone(file_entry)
        self.assertEqual(file_entry.number_of_sub_file_entries, 0)


if __name__ == "__main__":
    unittest.main()
