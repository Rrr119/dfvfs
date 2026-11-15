"""The LUKS2 file entry implementation."""

from dfvfs.lib import definitions
from dfvfs.lib import errors
from dfvfs.lib import luks2_helper
from dfvfs.resolver import resolver
from dfvfs.vfs import root_only_file_entry


class LUKS2FileEntry(root_only_file_entry.RootOnlyFileEntry):
    """File system file entry that uses the LUKS2 back-end."""

    TYPE_INDICATOR = definitions.TYPE_INDICATOR_LUKS2

    def __init__(
        self, resolver_context, file_system, path_spec, is_root=False, is_virtual=False
    ):
        """Initializes the file entry object.

        Args:
          resolver_context (Context): resolver context.
          file_system (FileSystem): file system.
          path_spec (PathSpec): path specification.
          is_root (Optional[bool]): True if the file entry is the root file entry
              of the corresponding file system.
          is_virtual (Optional[bool]): True if the file entry is a virtual file

        Raises:
          BackEndError: when the LUKS2 volume is missing.
        """
        volume = file_system.GetLUKS2Volume()
        if volume is None:
            raise errors.BackEndError("Missing LUKS2 volume.")

        super().__init__(
            resolver_context,
            file_system,
            path_spec,
            is_root=is_root,
            is_virtual=is_virtual,
        )
        self._volume = volume
        self.entry_type = definitions.FILE_ENTRY_TYPE_FILE

    @property
    def size(self):
        """int: size of the file entry in bytes or None if not available."""
        return self._volume.get_size()

    def IsLocked(self):
        """Determines if the file entry is locked.

        Returns:
          bool: True if the file entry is locked.
        """
        return self._volume.is_locked

    def Unlock(self):
        """Unlocks the file entry.

        Returns:
          bool: True if the file entry was unlocked.
        """
        return luks2_helper.LUKS2UnlockVolume(
            self._volume, self.path_spec, resolver.Resolver.key_chain
        )
