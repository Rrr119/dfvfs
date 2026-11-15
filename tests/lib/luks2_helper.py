#!/usr/bin/env python3
"""Tests for the LUKS2 helper."""

import os
import unittest

from dfvfs.lib import luks2_helper

from tests import test_lib as shared_test_lib


class _FileObject:
    """File-like object for testing."""

    # pylint: disable=invalid-name

    def __init__(self, path):
        """Initializes a file-like object."""
        self._file_object = open(path, "rb")  # pylint: disable=consider-using-with

    def close(self):
        """Closes the file-like object."""
        self._file_object.close()

    def get_size(self):
        """Retrieves the size of the file-like object."""
        current_offset = self._file_object.tell()
        self._file_object.seek(0, os.SEEK_END)
        size = self._file_object.tell()
        self._file_object.seek(current_offset, os.SEEK_SET)
        return size

    def read(self, size=None):
        """Reads data from the file-like object."""
        return self._file_object.read(size)

    def seek(self, offset, whence=os.SEEK_SET):
        """Seeks within the file-like object."""
        return self._file_object.seek(offset, whence)


class LUKS2HeaderTest(shared_test_lib.BaseTestCase):
    """Tests the LUKS2 header."""

    def testOpen(self):
        """Tests the Open function."""
        test_path = self._GetTestFilePath(["luks2.raw"])
        self._SkipIfPathNotExists(test_path)

        file_object = _FileObject(test_path)
        try:
            header = luks2_helper.LUKS2Header.Open(file_object)
        finally:
            file_object.close()

        self.assertEqual(header.version, 2)
        self.assertEqual(header.header_size, 16384)
        self.assertEqual(header.checksum_algorithm, "sha256")
        self.assertEqual(header.header_offset, 0)
        self.assertEqual(len(header.uuid), 36)

        self.assertEqual(len(header.keyslots), 2)
        keyslot = header.keyslots[0]
        self.assertEqual(keyslot.af_hash, "sha256")
        self.assertEqual(keyslot.af_stripes, 4000)
        self.assertEqual(keyslot.area_encryption, "aes-xts-plain64")
        self.assertEqual(keyslot.area_key_size, 64)
        self.assertEqual(keyslot.area_offset, 32768)
        self.assertEqual(keyslot.key_size, 64)
        self.assertEqual(keyslot.kdf_type, "pbkdf2")

        self.assertEqual(len(header.segments), 1)
        segment = header.segments[0]
        self.assertEqual(segment.encryption, "aes-xts-plain64")
        self.assertEqual(segment.offset, 1572864)
        self.assertIsNone(segment.size)
        self.assertEqual(segment.sector_size, 4096)
        self.assertEqual(segment.type, "crypt")


class LUKS2VolumeTest(shared_test_lib.BaseTestCase):
    """Tests the LUKS2 volume."""

    _PASSWORD = "luks2-TEST"

    def testUnlockWithPassword(self):
        """Tests the Unlock function with a password."""
        test_path = self._GetTestFilePath(["luks2.raw"])
        self._SkipIfPathNotExists(test_path)

        file_object = _FileObject(test_path)
        try:
            volume = luks2_helper.LUKS2Volume(file_object)
            volume.Open()
            self.assertTrue(volume.Unlock(password=self._PASSWORD))

            self.assertEqual(volume.get_size(), 15204352)
            data = volume.read()
        finally:
            file_object.close()

        self.assertEqual(data[0:1024], b"\x00" * 1024)
        self.assertEqual(data[1080:1082], b"\x53\xef")

    def testUnlockWithKeyfile(self):
        """Tests the Unlock function with a key file."""
        test_path = self._GetTestFilePath(["luks2.raw"])
        keyfile_path = self._GetTestFilePath(["luks2.keyfile"])
        self._SkipIfPathNotExists(test_path)
        self._SkipIfPathNotExists(keyfile_path)

        file_object = _FileObject(test_path)
        try:
            volume = luks2_helper.LUKS2Volume(file_object)
            volume.Open()
            self.assertTrue(volume.Unlock(keyfile=keyfile_path))
            self.assertFalse(volume.is_locked)
        finally:
            file_object.close()

    def testUnlockWithInvalidPassword(self):
        """Tests the Unlock function with an invalid password."""
        test_path = self._GetTestFilePath(["luks2.raw"])
        self._SkipIfPathNotExists(test_path)

        file_object = _FileObject(test_path)
        try:
            volume = luks2_helper.LUKS2Volume(file_object)
            volume.Open()
            self.assertFalse(volume.Unlock(password="invalid"))
            self.assertTrue(volume.is_locked)
            with self.assertRaises(OSError):
                volume.read()
        finally:
            file_object.close()


if __name__ == "__main__":
    unittest.main()
