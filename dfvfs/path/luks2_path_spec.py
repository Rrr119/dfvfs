"""The LUKS2 path specification implementation."""

from dfvfs.lib import definitions
from dfvfs.path import factory
from dfvfs.path import path_spec


class LUKS2PathSpec(path_spec.PathSpec):
    """LUKS2 path specification.

    Attributes:
      keyfile (str): path of the key file.
      password (str): password.
    """

    TYPE_INDICATOR = definitions.TYPE_INDICATOR_LUKS2

    def __init__(self, keyfile=None, password=None, parent=None, **kwargs):
        """Initializes a path specification.

        Note that the LUKS2 path specification must have a parent.

        Args:
          keyfile (Optional[str]): path of the key file.
          password (Optional[str]): password.
          parent (Optional[PathSpec]): parent path specification.

        Raises:
          ValueError: when parent is not set.
        """
        if not parent:
            raise ValueError("Missing parent value.")

        super().__init__(parent=parent, **kwargs)
        self.keyfile = keyfile
        self.password = password

    @property
    def comparable(self):
        """str: comparable representation of the path specification."""
        string_parts = []

        if self.password:
            string_parts.append(f"password: {self.password:s}")
        if self.keyfile:
            string_parts.append(f"keyfile: {self.keyfile:s}")

        return self._GetComparable(sub_comparable_string=", ".join(string_parts))


factory.Factory.RegisterPathSpec(LUKS2PathSpec)
