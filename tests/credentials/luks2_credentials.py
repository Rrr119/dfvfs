#!/usr/bin/env python3
"""Tests for the LUKS2 credentials."""

import unittest

from dfvfs.credentials import luks2_credentials

from tests import test_lib as shared_test_lib


class LUKS2CredentialsTest(shared_test_lib.BaseTestCase):
    """Tests the LUKS2 credentials."""

    def testInitialize(self):
        """Tests the __init__ function."""
        test_credentials = luks2_credentials.LUKS2Credentials()
        self.assertIsNotNone(test_credentials)


if __name__ == "__main__":
    unittest.main()
