"""The LUKS2 file system implementation."""

from dfvfs.lib import definitions
from dfvfs.lib import errors
from dfvfs.lib import luks2_helper
from dfvfs.path import luks2_path_spec
from dfvfs.resolver import resolver
from dfvfs.vfs import luks2_file_entry
from dfvfs.vfs import root_only_file_system


class LUKS2FileSystem(root_only_file_system.RootOnlyFileSystem):
    """File system that uses the LUKS2 back-end."""

    TYPE_INDICATOR = definitions.TYPE_INDICATOR_LUKS2

    def __init__(self, resolver_context, path_spec):
        """Initializes a file system.

        Args:
          resolver_context (Context): resolver context.
          path_spec (PathSpec): a path specification.
        """
        super().__init__(resolver_context, path_spec)
        self._file_object = None
        self._volume = None

    def _Close(self):
        """Closes the file system.

        Raises:
          OSError: if the close failed.
        """
        if self._volume:
            self._volume.close()
        if self._file_object:
            self._file_object.close()

        self._file_object = None
        self._volume = None

    def _Open(self, mode="rb"):
        """Opens the file system defined by path specification.

        Args:
          mode (Optional[str]): file access mode. The default is 'rb'
              read-only binary.

        Raises:
          AccessError: if the access to open the file was denied.
          OSError: if the file system could not be opened.
          PathSpecError: if the path specification is incorrect.
          ValueError: if the path specification is invalid.
        """
        if not self._path_spec.HasParent():
            raise errors.PathSpecError("Unsupported path specification without parent.")

        resolver.Resolver.key_chain.ExtractCredentialsFromPathSpec(self._path_spec)

        file_object = resolver.Resolver.OpenFileObject(
            self._path_spec.parent, resolver_context=self._resolver_context
        )
        volume = luks2_helper.LUKS2Volume(file_object)
        volume.Open()

        keyfile = resolver.Resolver.key_chain.GetCredential(self._path_spec, "keyfile")
        password = resolver.Resolver.key_chain.GetCredential(
            self._path_spec, "password"
        )
        if keyfile is not None or password is not None:
            volume.Unlock(password=password, keyfile=keyfile)

        self._file_object = file_object
        self._volume = volume

    def GetLUKS2Volume(self):
        """Retrieves the LUKS2 volume.

        Returns:
          LUKS2Volume: LUKS2 volume.
        """
        return self._volume

    def GetFileEntryByPathSpec(self, path_spec):
        """Retrieves a file entry for a path specification.

        Args:
          path_spec (PathSpec): path specification.

        Returns:
          LUKS2FileEntry: file entry or None.
        """
        return luks2_file_entry.LUKS2FileEntry(
            self._resolver_context, self, path_spec, is_root=True, is_virtual=True
        )

    def GetRootFileEntry(self):
        """Retrieves the root file entry.

        Returns:
          LUKS2FileEntry: file entry or None.
        """
        path_spec = luks2_path_spec.LUKS2PathSpec(parent=self._path_spec.parent)
        return self.GetFileEntryByPathSpec(path_spec)
