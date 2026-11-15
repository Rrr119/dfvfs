"""The LUKS2 file-like object."""

from dfvfs.file_io import file_object_io
from dfvfs.lib import errors
from dfvfs.lib import luks2_helper
from dfvfs.resolver import resolver


class LUKS2File(file_object_io.FileObjectIO):
    """File input/output (IO) object using LUKS2."""

    def _OpenFileObject(self, path_spec):
        """Opens the file-like object defined by path specification.

        Args:
          path_spec (PathSpec): path specification.

        Returns:
          LUKS2Volume: LUKS2 volume file-like object.

        Raises:
          PathSpecError: if the path specification is incorrect.
        """
        if not path_spec.HasParent():
            raise errors.PathSpecError("Unsupported path specification without parent.")

        resolver.Resolver.key_chain.ExtractCredentialsFromPathSpec(path_spec)

        file_object = resolver.Resolver.OpenFileObject(
            path_spec.parent, resolver_context=self._resolver_context
        )
        volume = luks2_helper.LUKS2Volume(file_object)
        volume.Open()

        keyfile = resolver.Resolver.key_chain.GetCredential(path_spec, "keyfile")
        password = resolver.Resolver.key_chain.GetCredential(path_spec, "password")
        if keyfile is not None or password is not None:
            volume.Unlock(password=password, keyfile=keyfile)

        return volume

    @property
    def is_locked(self):
        """bool: True if the volume is locked."""
        return self._file_object.is_locked
