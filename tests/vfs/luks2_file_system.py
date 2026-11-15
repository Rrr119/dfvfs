#!/usr/bin/env python3
"""Tests for the LUKS2 file system implementation."""

import unittest

from dfvfs.lib import definitions
from dfvfs.path import factory as path_spec_factory
from dfvfs.resolver import context
from dfvfs.resolver import resolver
from dfvfs.vfs import luks2_file_system

from tests import test_lib as shared_test_lib


class LUKS2FileSystemTest(shared_test_lib.BaseTestCase):
    """Tests the LUKS2 file system."""

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

    def tearDown(self):
        """Cleans up the needed objects used throughout the test."""
        self._resolver_context.Empty()
        resolver.Resolver.key_chain.Empty()

    def testOpenAndClose(self):
        """Tests the Open and close functions."""
        file_system = luks2_file_system.LUKS2FileSystem(
            self._resolver_context, self._luks2_path_spec
        )
        self.assertIsNotNone(file_system)

        file_system.Open()
        self.assertIsNotNone(file_system.GetLUKS2Volume())

    def testFileEntryExistsByPathSpec(self):
        """Tests the FileEntryExistsByPathSpec function."""
        file_system = luks2_file_system.LUKS2FileSystem(
            self._resolver_context, self._luks2_path_spec
        )
        file_system.Open()

        self.assertTrue(file_system.FileEntryExistsByPathSpec(self._luks2_path_spec))

    def testGetFileEntryByPathSpec(self):
        """Tests the GetFileEntryByPathSpec function."""
        file_system = luks2_file_system.LUKS2FileSystem(
            self._resolver_context, self._luks2_path_spec
        )
        file_system.Open()

        file_entry = file_system.GetFileEntryByPathSpec(self._luks2_path_spec)
        self.assertIsNotNone(file_entry)
        self.assertEqual(file_entry.name, "")

    def testGetRootFileEntry(self):
        """Tests the GetRootFileEntry function."""
        file_system = luks2_file_system.LUKS2FileSystem(
            self._resolver_context, self._luks2_path_spec
        )
        file_system.Open()

        file_entry = file_system.GetRootFileEntry()
        self.assertIsNotNone(file_entry)
        self.assertEqual(file_entry.name, "")


if __name__ == "__main__":
    unittest.main()
