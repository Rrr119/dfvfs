"""The LUKS2 volume path specification resolver helper implementation."""

from dfvfs.file_io import luks2_file_io
from dfvfs.lib import definitions
from dfvfs.resolver_helpers import manager
from dfvfs.resolver_helpers import resolver_helper
from dfvfs.vfs import luks2_file_system


class LUKS2ResolverHelper(resolver_helper.ResolverHelper):
    """LUKS2 volume resolver helper."""

    TYPE_INDICATOR = definitions.TYPE_INDICATOR_LUKS2

    def NewFileObject(self, resolver_context, path_spec):
        """Creates a new file input/output (IO) object.

        Args:
          resolver_context (Context): resolver context.
          path_spec (PathSpec): a path specification.

        Returns:
          LUKS2File: file input/output (IO) object.
        """
        return luks2_file_io.LUKS2File(resolver_context, path_spec)

    def NewFileSystem(self, resolver_context, path_spec):
        """Creates a new file system.

        Args:
          resolver_context (Context): resolver context.
          path_spec (PathSpec): a path specification.

        Returns:
          LUKS2FileSystem: file system.
        """
        return luks2_file_system.LUKS2FileSystem(resolver_context, path_spec)


manager.ResolverHelperManager.RegisterHelper(LUKS2ResolverHelper())
