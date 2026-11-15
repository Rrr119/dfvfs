#!/usr/bin/env python3
"""Tests for the LUKS2 file-like object implementation."""

import unittest

from dfvfs.lib import definitions
from dfvfs.path import ext_path_spec
from dfvfs.path import factory as path_spec_factory
from dfvfs.resolver import context
from dfvfs.resolver import resolver

from tests import test_lib as shared_test_lib


class LUKS2FileTest(shared_test_lib.BaseTestCase):
    """Tests the LUKS2 file-like object."""

    _PASSWORD = "luks2-TEST"

    def setUp(self):
        """Sets up the needed objects used throughout the test."""
        resolver.Resolver.key_chain.Empty()
        self._resolver_context = context.Context()
        test_path = self._GetTestFilePath(["luks2.raw"])
        self._SkipIfPathNotExists(test_path)

        self._os_path_spec = path_spec_factory.Factory.NewPathSpec(
            definitions.TYPE_INDICATOR_OS, location=test_path
        )
        self._luks2_path_spec = path_spec_factory.Factory.NewPathSpec(
            definitions.TYPE_INDICATOR_LUKS2, parent=self._os_path_spec
        )

    def tearDown(self):
        """Cleans up the needed objects used throughout the test."""
        self._resolver_context.Empty()
        resolver.Resolver.key_chain.Empty()

    def testOpenCloseWithPathSpecPassword(self):
        """Tests the Open and close functions with a path specification password."""
        path_spec = path_spec_factory.Factory.NewPathSpec(
            definitions.TYPE_INDICATOR_LUKS2,
            parent=self._os_path_spec,
            password=self._PASSWORD,
        )
        file_object = resolver.Resolver.OpenFileObject(
            path_spec, resolver_context=self._resolver_context
        )

        self.assertFalse(file_object.is_locked)
        self.assertEqual(file_object.get_size(), 15204352)

        file_object.seek(1080)
        self.assertEqual(file_object.read(2), b"\x53\xef")

        file_object.seek(0)
        data = file_object.read()
        self.assertEqual(len(data), 15204352)

    def testOpenCloseWithPathSpecKeyfile(self):
        """Tests the Open and close functions with a path specification key file."""
        keyfile_path = self._GetTestFilePath(["luks2.keyfile"])
        self._SkipIfPathNotExists(keyfile_path)

        path_spec = path_spec_factory.Factory.NewPathSpec(
            definitions.TYPE_INDICATOR_LUKS2,
            keyfile=keyfile_path,
            parent=self._os_path_spec,
        )
        file_object = resolver.Resolver.OpenFileObject(
            path_spec, resolver_context=self._resolver_context
        )

        self.assertFalse(file_object.is_locked)
        file_object.seek(1080)
        self.assertEqual(file_object.read(2), b"\x53\xef")

    def testOpenCloseWithKeyChainPassword(self):
        """Tests the Open and close functions with a key chain password."""
        resolver.Resolver.key_chain.SetCredential(
            self._luks2_path_spec, "password", self._PASSWORD
        )
        file_object = resolver.Resolver.OpenFileObject(
            self._luks2_path_spec, resolver_context=self._resolver_context
        )

        self.assertFalse(file_object.is_locked)
        file_object.seek(1080)
        self.assertEqual(file_object.read(2), b"\x53\xef")

    def testOpenLocked(self):
        """Tests opening a locked volume."""
        file_object = resolver.Resolver.OpenFileObject(
            self._luks2_path_spec, resolver_context=self._resolver_context
        )

        self.assertTrue(file_object.is_locked)
        self.assertEqual(file_object.get_size(), 15204352)

        with self.assertRaises(OSError):
            file_object.read(1)

    def testInternalFileSystem(self):
        """Tests accessing a file in the internal ext file system."""
        path_spec = path_spec_factory.Factory.NewPathSpec(
            definitions.TYPE_INDICATOR_LUKS2,
            parent=self._os_path_spec,
            password=self._PASSWORD,
        )
        file_path_spec = ext_path_spec.EXTPathSpec(
            location="/passwords.txt", parent=path_spec
        )
        file_object = resolver.Resolver.OpenFileObject(
            file_path_spec, resolver_context=self._resolver_context
        )

        self.assertEqual(file_object.get_size(), 116)
        self.assertEqual(
            file_object.read(),
            (
                b"place,user,password\n"
                b"bank,joesmith,superrich\n"
                b"alarm system,-,1234\n"
                b"treasure chest,-,1111\n"
                b"uber secret laire,admin,admin\n"
            ),
        )


if __name__ == "__main__":
    unittest.main()
