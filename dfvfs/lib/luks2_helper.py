"""Helper functions for Linux Unified Key Setup (LUKS) 2 support."""

import base64
import hashlib
import hmac
import json
import os
import struct

from dfvfs.lib import errors

_LUKS2_BINARY_HEADER_SIZE = 4096
_LUKS2_CHECKSUM_OFFSET = 448
_LUKS2_CHECKSUM_SIZE = 64
_LUKS2_MAGIC = b"LUKS\xba\xbe"
_LUKS2_MAXIMUM_HEADER_SIZE = 4 * 1024 * 1024
_LUKS2_MINIMUM_HEADER_SIZE = 16 * 1024
_LUKS2_SECONDARY_MAGIC = b"SKUL\xba\xbe"
_LUKS2_SECTOR_SIZE = 512


def _GetJSONInteger(json_object, name, default=None):
    """Retrieves an integer from a JSON object.

    Args:
      json_object (dict[str, object]): JSON object.
      name (str): name of the value.
      default (Optional[int]): default value if not available.

    Returns:
      int: integer value.

    Raises:
      ValueError: if the value is missing or invalid.
    """
    value = json_object.get(name, default)
    if value is None:
        raise ValueError(f"Missing LUKS2 JSON value: {name:s}.")

    try:
        return int(value)
    except (TypeError, ValueError) as exception:
        raise ValueError(f"Invalid LUKS2 JSON value: {name:s}.") from exception


def _GetJSONString(json_object, name, default=None):
    """Retrieves a string from a JSON object.

    Args:
      json_object (dict[str, object]): JSON object.
      name (str): name of the value.
      default (Optional[str]): default value if not available.

    Returns:
      str: string value.

    Raises:
      ValueError: if the value is missing or invalid.
    """
    value = json_object.get(name, default)
    if not isinstance(value, str):
        raise ValueError(f"Missing or invalid LUKS2 JSON value: {name:s}.")

    return value


class LUKS2Keyslot:
    """LUKS2 keyslot.

    Attributes:
      af_hash (str): anti-forensic hash algorithm.
      af_stripes (int): number of anti-forensic stripes.
      af_type (str): anti-forensic function type.
      area_encryption (str): keyslot area encryption.
      area_key_size (int): keyslot area key size.
      area_offset (int): keyslot area offset.
      area_size (int): keyslot area size.
      identifier (int): keyslot identifier.
      key_size (int): volume key size.
      kdf_parameters (dict[str, object]): key derivation function parameters.
      kdf_type (str): key derivation function type.
      type (str): keyslot type.
    """

    def __init__(self, identifier, json_object):
        """Initializes a keyslot.

        Args:
          identifier (int): keyslot identifier.
          json_object (dict[str, object]): JSON object.

        Raises:
          ValueError: if the keyslot is invalid.
        """
        if not isinstance(json_object, dict):
            raise ValueError(f"Invalid LUKS2 keyslot: {identifier:d}.")

        area_json = json_object.get("area")
        af_json = json_object.get("af")
        kdf_json = json_object.get("kdf")
        if not isinstance(area_json, dict):
            raise ValueError(f"Invalid LUKS2 keyslot area: {identifier:d}.")
        if not isinstance(af_json, dict):
            raise ValueError(f"Invalid LUKS2 keyslot AF: {identifier:d}.")
        if not isinstance(kdf_json, dict):
            raise ValueError(f"Invalid LUKS2 keyslot KDF: {identifier:d}.")

        self.af_hash = _GetJSONString(af_json, "hash")
        self.af_stripes = _GetJSONInteger(af_json, "stripes")
        self.af_type = _GetJSONString(af_json, "type")
        self.area_encryption = _GetJSONString(area_json, "encryption")
        self.area_key_size = _GetJSONInteger(area_json, "key_size")
        self.area_offset = _GetJSONInteger(area_json, "offset")
        self.area_size = _GetJSONInteger(area_json, "size")
        self.identifier = identifier
        self.key_size = _GetJSONInteger(json_object, "key_size")
        self.kdf_parameters = kdf_json
        self.kdf_type = _GetJSONString(kdf_json, "type")
        self.type = _GetJSONString(json_object, "type")

        if self.af_stripes < 1:
            raise ValueError(f"Invalid LUKS2 keyslot stripes: {identifier:d}.")
        if self.area_offset < 0 or self.area_size < 1:
            raise ValueError(f"Invalid LUKS2 keyslot area: {identifier:d}.")
        if self.area_key_size < 1:
            raise ValueError(f"Invalid LUKS2 keyslot area key size: {identifier:d}.")
        if self.key_size < 1:
            raise ValueError(f"Invalid LUKS2 keyslot key size: {identifier:d}.")


class LUKS2Segment:
    """LUKS2 data segment.

    Attributes:
      encryption (str): segment encryption.
      identifier (int): segment identifier.
      iv_tweak (int): initial vector tweak.
      offset (int): segment offset.
      sector_size (int): encryption sector size.
      size (Optional[int]): segment size or None if dynamic.
      type (str): segment type.
    """

    def __init__(self, identifier, json_object):
        """Initializes a data segment.

        Args:
          identifier (int): segment identifier.
          json_object (dict[str, object]): JSON object.

        Raises:
          ValueError: if the segment is invalid.
        """
        if not isinstance(json_object, dict):
            raise ValueError(f"Invalid LUKS2 segment: {identifier:d}.")

        self.encryption = _GetJSONString(json_object, "encryption")
        self.identifier = identifier
        self.iv_tweak = _GetJSONInteger(json_object, "iv_tweak", default=0)
        self.offset = _GetJSONInteger(json_object, "offset")
        self.sector_size = _GetJSONInteger(json_object, "sector_size", default=512)
        self.type = _GetJSONString(json_object, "type")

        size = json_object.get("size")
        if isinstance(size, str) and size == "dynamic":
            self.size = None
        else:
            self.size = _GetJSONInteger(json_object, "size")

        if self.offset < 0:
            raise ValueError(f"Invalid LUKS2 segment offset: {identifier:d}.")
        if self.sector_size < 512 or self.sector_size > 4096:
            raise ValueError(f"Invalid LUKS2 segment sector size: {identifier:d}.")
        if self.sector_size & (self.sector_size - 1) != 0:
            raise ValueError(f"Invalid LUKS2 segment sector size: {identifier:d}.")
        if self.size is not None and self.size < 1:
            raise ValueError(f"Invalid LUKS2 segment size: {identifier:d}.")


class LUKS2Header:
    """LUKS2 header.

    Attributes:
      checksum_algorithm (str): checksum algorithm.
      digests (dict[int, dict[str, object]]): digests by identifier.
      header_offset (int): header offset.
      header_size (int): header size.
      keyslots (dict[int, LUKS2Keyslot]): keyslots by identifier.
      label (str): label.
      sequence_identifier (int): sequence identifier.
      segments (dict[int, LUKS2Segment]): data segments by identifier.
      subsystem (str): subsystem.
      uuid (str): volume UUID.
      version (int): format version.
    """

    def __init__(self):
        """Initializes a header."""
        self.checksum_algorithm = None
        self.header_offset = None
        self.header_size = None
        self.keyslots = {}
        self.label = None
        self.sequence_identifier = None
        self.segments = {}
        self.subsystem = None
        self.uuid = None
        self.version = None

        self.digests = {}
        self._json_object = None

    @classmethod
    def Open(cls, file_object):
        """Reads a LUKS2 header from a file-like object.

        Args:
          file_object (FileIO): file-like object.

        Returns:
          LUKS2Header: LUKS2 header.

        Raises:
          ValueError: if the header is invalid.
        """
        file_object.seek(0)
        binary_header = file_object.read(_LUKS2_BINARY_HEADER_SIZE)
        if len(binary_header) < _LUKS2_BINARY_HEADER_SIZE:
            raise ValueError("Unable to read LUKS2 binary header.")

        primary_header = cls()
        try:
            primary_header._Read(file_object, 0, _LUKS2_MAGIC)
            return primary_header
        except ValueError as exception:
            primary_exception = exception

        header_size = int.from_bytes(binary_header[8:16], byteorder="big")
        secondary_offsets = []
        if _LUKS2_MINIMUM_HEADER_SIZE <= header_size <= _LUKS2_MAXIMUM_HEADER_SIZE:
            secondary_offsets.append(header_size)
        if _LUKS2_MINIMUM_HEADER_SIZE not in secondary_offsets:
            secondary_offsets.append(_LUKS2_MINIMUM_HEADER_SIZE)

        for secondary_offset in secondary_offsets:
            secondary_header = cls()
            try:
                secondary_header._Read(
                    file_object, secondary_offset, _LUKS2_SECONDARY_MAGIC
                )
            except ValueError:
                continue

            return secondary_header

        raise primary_exception

    def _Read(self, file_object, offset, expected_magic):
        """Reads a LUKS2 header at a specific offset.

        Args:
          file_object (FileIO): file-like object.
          offset (int): offset of the header.
          expected_magic (bytes): expected magic.

        Raises:
          ValueError: if the header is invalid.
        """
        file_object.seek(offset)
        binary_header = file_object.read(_LUKS2_BINARY_HEADER_SIZE)
        if len(binary_header) < _LUKS2_BINARY_HEADER_SIZE:
            raise ValueError("Unable to read LUKS2 binary header.")

        if binary_header[0:6] != expected_magic:
            raise ValueError("Unsupported LUKS2 header signature.")

        version = int.from_bytes(binary_header[6:8], byteorder="big")
        if version != 2:
            raise ValueError(f"Unsupported LUKS2 version: {version:d}.")

        header_size = int.from_bytes(binary_header[8:16], byteorder="big")
        if (
            header_size < _LUKS2_MINIMUM_HEADER_SIZE
            or header_size > _LUKS2_MAXIMUM_HEADER_SIZE
        ):
            raise ValueError(f"Unsupported LUKS2 header size: {header_size:d}.")

        header_offset = int.from_bytes(binary_header[256:264], byteorder="big")
        if header_offset != offset:
            raise ValueError("Invalid LUKS2 header offset.")

        json_area_size = header_size - _LUKS2_BINARY_HEADER_SIZE
        file_object.seek(offset + _LUKS2_BINARY_HEADER_SIZE)
        json_area = file_object.read(json_area_size)
        if len(json_area) != json_area_size:
            raise ValueError("Unable to read LUKS2 JSON area.")

        checksum_algorithm = binary_header[72:104].split(b"\x00", 1)[0]
        try:
            checksum_algorithm = checksum_algorithm.decode("ascii")
            checksum_hasher = hashlib.new(checksum_algorithm)
        except (UnicodeDecodeError, ValueError) as exception:
            raise ValueError("Unsupported LUKS2 checksum algorithm.") from exception

        calculated_header = bytearray(binary_header)
        checksum_end_offset = _LUKS2_CHECKSUM_OFFSET + _LUKS2_CHECKSUM_SIZE
        empty_checksum = b"\x00" * _LUKS2_CHECKSUM_SIZE
        calculated_header[_LUKS2_CHECKSUM_OFFSET:checksum_end_offset] = empty_checksum
        checksum_hasher.update(calculated_header)
        checksum_hasher.update(json_area)
        calculated_checksum = checksum_hasher.digest()

        stored_checksum = binary_header[
            _LUKS2_CHECKSUM_OFFSET : _LUKS2_CHECKSUM_OFFSET + len(calculated_checksum)
        ]
        if not hmac.compare_digest(calculated_checksum, stored_checksum):
            raise ValueError("Invalid LUKS2 header checksum.")

        json_data = json_area.split(b"\x00", 1)[0]
        try:
            json_object = json.loads(json_data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exception:
            raise ValueError("Unable to parse LUKS2 JSON area.") from exception

        if not isinstance(json_object, dict):
            raise ValueError("Invalid LUKS2 JSON object.")

        self.checksum_algorithm = checksum_algorithm
        self.header_offset = header_offset
        self.header_size = header_size
        self.label = (
            binary_header[24:72].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        )
        self.sequence_identifier = int.from_bytes(binary_header[16:24], byteorder="big")
        self.subsystem = (
            binary_header[208:256]
            .split(b"\x00", 1)[0]
            .decode("utf-8", errors="replace")
        )
        self.uuid = (
            binary_header[168:208]
            .split(b"\x00", 1)[0]
            .decode("utf-8", errors="replace")
        )
        self.version = version
        self._json_object = json_object

        self._ReadKeyslots(json_object)
        self._ReadSegments(json_object)

    def _ReadKeyslots(self, json_object):
        """Reads the keyslots from the JSON object.

        Args:
          json_object (dict[str, object]): JSON object.

        Raises:
          ValueError: if the keyslots are invalid.
        """
        keyslots_json = json_object.get("keyslots", {})
        if not isinstance(keyslots_json, dict):
            raise ValueError("Invalid LUKS2 keyslots.")

        for identifier, keyslot_json in keyslots_json.items():
            try:
                identifier = int(identifier)
            except (TypeError, ValueError) as exception:
                raise ValueError("Invalid LUKS2 keyslot identifier.") from exception

            keyslot = LUKS2Keyslot(identifier, keyslot_json)
            self.keyslots[identifier] = keyslot

    def _ReadSegments(self, json_object):
        """Reads the data segments from the JSON object.

        Args:
          json_object (dict[str, object]): JSON object.

        Raises:
          ValueError: if the segments are invalid.
        """
        segments_json = json_object.get("segments", {})
        if not isinstance(segments_json, dict):
            raise ValueError("Invalid LUKS2 segments.")

        for identifier, segment_json in segments_json.items():
            try:
                identifier = int(identifier)
            except (TypeError, ValueError) as exception:
                raise ValueError("Invalid LUKS2 segment identifier.") from exception

            segment = LUKS2Segment(identifier, segment_json)
            self.segments[identifier] = segment

        digests_json = json_object.get("digests", {})
        if not isinstance(digests_json, dict):
            raise ValueError("Invalid LUKS2 digests.")

        for identifier, digest_json in digests_json.items():
            if not isinstance(digest_json, dict):
                raise ValueError(f"Invalid LUKS2 digest: {identifier!s}.")
            self.digests[int(identifier)] = digest_json


class LUKS2Volume:
    """LUKS2 volume providing a decrypted file-like object.

    Attributes:
      header (LUKS2Header): LUKS2 header.
      segment (LUKS2Segment): selected data segment.
    """

    # pylint: disable=invalid-name

    def __init__(self, file_object):
        """Initializes a LUKS2 volume.

        Args:
          file_object (FileIO): file-like object containing the encrypted volume.
        """
        super().__init__()
        self._current_offset = 0
        self._file_object = file_object
        self._segment_data_offset = 0
        self._size = 0
        self._volume_key = None

        self.header = None
        self.segment = None

    def _ReadFileObjectData(self, offset, size):
        """Reads data from the encrypted file-like object.

        Args:
          offset (int): offset in the volume.
          size (int): number of bytes to read.

        Returns:
          bytes: data read.

        Raises:
          OSError: if the data cannot be read.
        """
        self._file_object.seek(self._segment_data_offset + offset)
        data = self._file_object.read(size)
        if len(data) != size:
            raise OSError("Unable to read LUKS2 encrypted data.")
        return data

    def _VerifyVolumeKey(self, keyslot, volume_key):
        """Verifies a volume key using the matching LUKS2 digest.

        Args:
          keyslot (LUKS2Keyslot): keyslot.
          volume_key (bytes): volume key.

        Returns:
          bool: True if the volume key is valid.
        """
        for digest_json in self.header.digests.values():
            digest_keyslots = digest_json.get("keyslots", [])
            if str(keyslot.identifier) not in digest_keyslots:
                continue

            if digest_json.get("type") != "pbkdf2":
                continue

            try:
                digest = base64.b64decode(digest_json["digest"])
                digest_hash = digest_json["hash"]
                digest_iterations = int(digest_json["iterations"])
                digest_salt = base64.b64decode(digest_json["salt"])
            except (KeyError, TypeError, ValueError):
                continue

            calculated_digest = hashlib.pbkdf2_hmac(
                digest_hash,
                volume_key,
                digest_salt,
                digest_iterations,
                dklen=len(digest),
            )
            if hmac.compare_digest(calculated_digest, digest):
                return True

        return False

    def close(self):
        """Closes the LUKS2 volume."""
        self._volume_key = None

    def get_offset(self):
        """Retrieves the current offset into the decrypted data.

        Returns:
          int: current offset.
        """
        return self._current_offset

    def get_size(self):
        """Retrieves the size of the decrypted data.

        Returns:
          int: size of the decrypted data.
        """
        return self._size

    @property
    def is_locked(self):
        """bool: True if the volume is locked."""
        return self._volume_key is None

    def Open(self):
        """Opens the LUKS2 volume.

        Raises:
          NotSupported: if the data segment type is not supported.
          ValueError: if the volume is invalid or unsupported.
        """
        self.header = LUKS2Header.Open(self._file_object)
        if not self.header.segments:
            raise ValueError("Missing LUKS2 data segment.")

        segment_identifiers = sorted(self.header.segments)
        self.segment = self.header.segments[
            0 if 0 in self.header.segments else segment_identifiers[0]
        ]
        if self.segment.type != "crypt":
            raise errors.NotSupported(
                f"Unsupported LUKS2 segment type: {self.segment.type:s}."
            )

        file_size = self._file_object.get_size()
        if self.segment.offset > file_size:
            raise ValueError("LUKS2 data segment offset is beyond the volume size.")

        if self.segment.size is None:
            segment_size = file_size - self.segment.offset
        else:
            segment_size = self.segment.size

        if segment_size < 0 or self.segment.offset + segment_size > file_size:
            raise ValueError("Invalid LUKS2 data segment size.")

        self._segment_data_offset = self.segment.offset
        self._size = segment_size
        self._current_offset = 0

    def read(self, size=None):
        """Reads decrypted data at the current offset.

        Args:
          size (Optional[int]): number of bytes to read, where None is all
              remaining data.

        Returns:
          bytes: decrypted data.

        Raises:
          OSError: if the volume is locked or the read failed.
        """
        if self.is_locked:
            raise OSError("LUKS2 volume is locked.")

        if self._current_offset >= self._size:
            return b""

        if size is None:
            size = self._size - self._current_offset
        else:
            size = min(size, self._size - self._current_offset)

        if size <= 0:
            return b""

        sector_size = self.segment.sector_size
        read_offset = self._current_offset
        read_end = read_offset + size
        aligned_offset = read_offset - (read_offset % sector_size)
        aligned_end = read_end + (-read_end % sector_size)
        aligned_end = min(aligned_end, self._size)

        encrypted_data = self._ReadFileObjectData(
            aligned_offset, aligned_end - aligned_offset
        )
        if len(encrypted_data) % sector_size != 0:
            padding_size = sector_size - (len(encrypted_data) % sector_size)
            encrypted_data += b"\x00" * padding_size

        decrypted_data = _DecryptStorage(
            encrypted_data,
            self._volume_key,
            self.segment.encryption,
            sector_size=sector_size,
            sector_offset=aligned_offset // _LUKS2_SECTOR_SIZE + self.segment.iv_tweak,
        )

        data_offset = read_offset - aligned_offset
        data = decrypted_data[data_offset : data_offset + size]
        self._current_offset += len(data)
        return data

    def seek(self, offset, whence=os.SEEK_SET):
        """Seeks to an offset within the decrypted data.

        Args:
          offset (int): offset to seek to.
          whence (Optional[int]): value that indicates whether offset is an
              absolute or relative position within the file.

        Raises:
          OSError: if the seek failed.
        """
        if whence == os.SEEK_CUR:
            offset += self._current_offset
        elif whence == os.SEEK_END:
            offset += self._size
        elif whence != os.SEEK_SET:
            raise OSError("Unsupported whence.")

        if offset < 0:
            raise OSError("Invalid offset value less than zero.")

        self._current_offset = offset

    def Unlock(self, password=None, keyfile=None):
        """Unlocks the LUKS2 volume.

        Args:
          password (Optional[str]): password.
          keyfile (Optional[str]): path of the key file.

        Returns:
          bool: True if the volume was unlocked.
        """
        credentials = []
        if keyfile:
            with open(keyfile, "rb") as file_object:
                credentials.append(file_object.read())

        if password is not None:
            if isinstance(password, str):
                password = password.encode("utf-8")
            credentials.append(password)

        for keyslot in sorted(
            self.header.keyslots.values(), key=lambda value: value.identifier
        ):
            for credential in credentials:
                try:
                    volume_key = _UnlockKeyslot(self._file_object, keyslot, credential)
                except (errors.NotSupported, ValueError):
                    continue

                if volume_key and self._VerifyVolumeKey(keyslot, volume_key):
                    self._volume_key = volume_key
                    return True

        return False


def _AFDiffuse(data, hash_name):
    """Diffuses anti-forensic data.

    Args:
      data (bytes): data to diffuse.
      hash_name (str): hash algorithm name.

    Returns:
      bytes: diffused data.
    """
    digest_size = hashlib.new(hash_name).digest_size
    output_data = bytearray()

    for block_index, data_offset in enumerate(range(0, len(data), digest_size)):
        hasher = hashlib.new(hash_name)
        hasher.update(struct.pack(">I", block_index))
        hasher.update(data[data_offset : data_offset + digest_size])
        output_data.extend(hasher.digest())

    return bytes(output_data)


def _AFMerge(data, key_size, stripes, hash_name):
    """Merges anti-forensic split data.

    Args:
      data (bytes): anti-forensic split data.
      key_size (int): size of the volume key.
      stripes (int): number of stripes.
      hash_name (str): hash algorithm name.

    Returns:
      bytes: volume key.

    Raises:
      ValueError: if the anti-forensic data is too small.
    """
    required_size = key_size * stripes
    if len(data) < required_size:
        raise ValueError("LUKS2 keyslot anti-forensic data is too small.")

    buffer = bytes(key_size)
    for stripe_index in range(stripes - 1):
        stripe_offset = stripe_index * key_size
        stripe = data[stripe_offset : stripe_offset + key_size]
        buffer = bytes(value_a ^ value_b for value_a, value_b in zip(stripe, buffer))
        buffer = _AFDiffuse(buffer, hash_name)

    stripe_offset = (stripes - 1) * key_size
    stripe = data[stripe_offset : stripe_offset + key_size]
    return bytes(value_a ^ value_b for value_a, value_b in zip(stripe, buffer))


def _DecryptAESCBC(data, key, iv):
    """Decrypts AES-CBC data.

    Args:
      data (bytes): encrypted data.
      key (bytes): AES key.
      iv (bytes): initial vector.

    Returns:
      bytes: decrypted data.
    """
    # pylint: disable=import-outside-toplevel
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def _DecryptAESXTS(data, key, tweak):
    """Decrypts AES-XTS data.

    Args:
      data (bytes): encrypted data.
      key (bytes): AES-XTS key.
      tweak (bytes): initial vector.

    Returns:
      bytes: decrypted data.
    """
    # pylint: disable=import-outside-toplevel
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    decryptor = Cipher(algorithms.AES(key), modes.XTS(tweak)).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def _DecryptStorage(data, key, encryption, sector_size, sector_offset=0):
    """Decrypts LUKS sector-based storage data.

    Args:
      data (bytes): encrypted data.
      key (bytes): encryption key.
      encryption (str): encryption specification.
      sector_size (int): number of bytes per sector.
      sector_offset (Optional[int]): initial sector number.

    Returns:
      bytes: decrypted data.

    Raises:
      NotSupported: if the encryption is not supported.
    """
    cipher_name, cipher_mode, iv_mode = _ParseEncryption(encryption)
    if cipher_name != "aes":
        raise errors.NotSupported(f"Unsupported LUKS2 cipher: {cipher_name:s}.")

    if len(data) % sector_size != 0:
        raise ValueError("LUKS2 encrypted data is not sector aligned.")

    decrypted_data = bytearray()
    for data_offset in range(0, len(data), sector_size):
        sector_data = data[data_offset : data_offset + sector_size]
        sector = sector_offset + data_offset // _LUKS2_SECTOR_SIZE
        iv = _GenerateInitialVector(iv_mode, sector, key)

        if cipher_mode == "cbc":
            decrypted_sector = _DecryptAESCBC(sector_data, key, iv)
        elif cipher_mode == "xts":
            decrypted_sector = _DecryptAESXTS(sector_data, key, iv)
        else:
            raise errors.NotSupported(
                f"Unsupported LUKS2 cipher mode: {cipher_mode:s}."
            )

        decrypted_data.extend(decrypted_sector)

    return bytes(decrypted_data)


def _DeriveKeyslotKey(keyslot, credential):
    """Derives a keyslot key from a credential.

    Args:
      keyslot (LUKS2Keyslot): keyslot.
      credential (bytes): credential data.

    Returns:
      bytes: derived key.

    Raises:
      NotSupported: if the key derivation function is not supported.
      ValueError: if the keyslot KDF parameters are invalid.
    """
    kdf_parameters = keyslot.kdf_parameters
    try:
        salt = base64.b64decode(kdf_parameters["salt"])
    except (KeyError, TypeError, ValueError) as exception:
        raise ValueError("Invalid LUKS2 keyslot KDF salt.") from exception
    if len(salt) != 32:
        raise ValueError("Invalid LUKS2 keyslot KDF salt size.")

    if keyslot.kdf_type == "pbkdf2":
        try:
            hash_name = _GetJSONString(kdf_parameters, "hash")
            iterations = _GetJSONInteger(kdf_parameters, "iterations")
        except ValueError as exception:
            raise ValueError("Invalid LUKS2 PBKDF2 parameters.") from exception

        return hashlib.pbkdf2_hmac(
            hash_name,
            credential,
            salt,
            iterations,
            dklen=keyslot.area_key_size,
        )

    if keyslot.kdf_type in ("argon2i", "argon2id"):
        # pylint: disable=import-outside-toplevel
        from argon2.low_level import hash_secret_raw, Type

        try:
            time_cost = _GetJSONInteger(kdf_parameters, "time")
            memory_cost = _GetJSONInteger(kdf_parameters, "memory")
            parallelism = _GetJSONInteger(kdf_parameters, "cpus")
        except ValueError as exception:
            raise ValueError("Invalid LUKS2 Argon2 parameters.") from exception

        argon_type = Type.I if keyslot.kdf_type == "argon2i" else Type.ID
        return hash_secret_raw(
            secret=credential,
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=keyslot.area_key_size,
            type=argon_type,
            version=19,
        )

    raise errors.NotSupported(
        f"Unsupported LUKS2 key derivation function: {keyslot.kdf_type:s}."
    )


def _GenerateInitialVector(iv_mode, sector, key):
    """Generates a sector initial vector.

    Args:
      iv_mode (str): initial vector mode.
      sector (int): sector number.
      key (bytes): encryption key.

    Returns:
      bytes: initial vector.

    Raises:
      NotSupported: if the initial vector mode is not supported.
    """
    iv = bytearray(16)

    if iv_mode == "plain":
        iv[0:4] = struct.pack("<I", sector & 0xFFFFFFFF)
    elif iv_mode == "plain64":
        iv[0:8] = struct.pack("<Q", sector)
    elif iv_mode is None:
        raise errors.NotSupported("Missing LUKS2 initial vector mode.")
    elif iv_mode.startswith("essiv:"):
        # pylint: disable=import-outside-toplevel
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        hash_name = iv_mode.split(":", 1)[1]
        essiv_key = hashlib.new(hash_name, key).digest()
        if len(essiv_key) not in (16, 24, 32):
            raise errors.NotSupported(
                f"Unsupported LUKS2 ESSIV hash size: {len(essiv_key):d}."
            )

        iv[0:8] = struct.pack("<Q", sector)
        encryptor = Cipher(algorithms.AES(essiv_key), modes.ECB()).encryptor()
        iv = bytearray(encryptor.update(iv) + encryptor.finalize())
    else:
        raise errors.NotSupported(
            f"Unsupported LUKS2 initial vector mode: {iv_mode:s}."
        )

    return bytes(iv)


def _ParseEncryption(encryption):
    """Parses a LUKS encryption specification.

    Args:
      encryption (str): encryption specification.

    Returns:
      tuple[str, str, str]: cipher name, cipher mode and initial vector mode.

    Raises:
      ValueError: if the encryption specification is invalid.
    """
    cipher_name, separator, mode_specification = encryption.partition("-")
    if not separator:
        raise ValueError(f"Invalid LUKS2 encryption: {encryption:s}.")

    cipher_mode, separator, iv_mode = mode_specification.partition("-")
    if not separator:
        iv_mode = None

    return cipher_name.lower(), cipher_mode.lower(), iv_mode


def _UnlockKeyslot(file_object, keyslot, credential):
    """Unlocks a LUKS2 keyslot.

    Args:
      file_object (FileIO): file-like object containing the encrypted volume.
      keyslot (LUKS2Keyslot): keyslot.
      credential (bytes): credential data.

    Returns:
      bytes: volume key or None if the keyslot could not be unlocked.

    Raises:
      NotSupported: if the keyslot uses unsupported functionality.
      ValueError: if the keyslot is invalid.
    """
    if keyslot.type != "luks2":
        raise errors.NotSupported(f"Unsupported LUKS2 keyslot type: {keyslot.type:s}.")
    if keyslot.af_type != "luks1":
        raise errors.NotSupported(f"Unsupported LUKS2 AF type: {keyslot.af_type:s}.")

    keyslot_key = _DeriveKeyslotKey(keyslot, credential)
    anti_forensic_size = keyslot.key_size * keyslot.af_stripes
    anti_forensic_size += -anti_forensic_size % _LUKS2_SECTOR_SIZE
    if anti_forensic_size > keyslot.area_size:
        raise ValueError("LUKS2 keyslot area is too small.")

    file_object.seek(keyslot.area_offset)
    encrypted_data = file_object.read(anti_forensic_size)
    if len(encrypted_data) != anti_forensic_size:
        raise ValueError("Unable to read LUKS2 keyslot area.")

    anti_forensic_data = _DecryptStorage(
        encrypted_data,
        keyslot_key,
        keyslot.area_encryption,
        sector_size=_LUKS2_SECTOR_SIZE,
    )
    return _AFMerge(
        anti_forensic_data,
        keyslot.key_size,
        keyslot.af_stripes,
        keyslot.af_hash,
    )


def LUKS2UnlockVolume(volume, path_spec, key_chain):
    """Unlocks a LUKS2 volume using the path specification.

    Args:
      volume (LUKS2Volume): LUKS2 volume.
      path_spec (PathSpec): path specification.
      key_chain (KeyChain): key chain.

    Returns:
      bool: True if the volume was unlocked.
    """
    if not volume.is_locked:
        return True

    keyfile = key_chain.GetCredential(path_spec, "keyfile")
    password = key_chain.GetCredential(path_spec, "password")
    if keyfile is None and password is None:
        return False

    return volume.Unlock(password=password, keyfile=keyfile)
