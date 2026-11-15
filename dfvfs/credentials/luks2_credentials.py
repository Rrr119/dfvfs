"""The LUKS2 credentials."""

from dfvfs.credentials import credentials
from dfvfs.credentials import manager
from dfvfs.lib import definitions


class LUKS2Credentials(credentials.Credentials):
    """LUKS2 credentials."""

    CREDENTIALS = frozenset(["keyfile", "password"])

    TYPE_INDICATOR = definitions.TYPE_INDICATOR_LUKS2


manager.CredentialsManager.RegisterCredentials(LUKS2Credentials())
