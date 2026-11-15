#!/usr/bin/env python3
"""Tests for the LUKS2 resolver helper implementation."""

import unittest

from dfvfs.lib import definitions
from dfvfs.path import factory as path_spec_factory
from dfvfs.resolver_helpers import luks2_resolver_helper

from tests.resolver_helpers import test_lib


class LUKS2ResolverHelperTest(test_lib.ResolverHelperTestCase):
    """Tests for the LUKS2 resolver helper implementation."""

    def setUp(self):
        """Sets up the needed objects used throughout the test."""
        super().setUp()

        test_path = self._GetTestFilePath(["luks2.raw"])
        self._SkipIfPathNotExists(test_path)

        test_os_path_spec = path_spec_factory.Factory.NewPathSpec(
            definitions.TYPE_INDICATOR_OS, location=test_path
        )
        self._luks2_path_spec = path_spec_factory.Factory.NewPathSpec(
            definitions.TYPE_INDICATOR_LUKS2, parent=test_os_path_spec
        )

    def testNewFileObject(self):
        """Tests the NewFileObject function."""
        resolver_helper_object = luks2_resolver_helper.LUKS2ResolverHelper()
        self._TestNewFileObject(resolver_helper_object, self._luks2_path_spec)

    def testNewFileSystem(self):
        """Tests the NewFileSystem function."""
        resolver_helper_object = luks2_resolver_helper.LUKS2ResolverHelper()
        self._TestNewFileSystem(resolver_helper_object, self._luks2_path_spec)


if __name__ == "__main__":
    unittest.main()
