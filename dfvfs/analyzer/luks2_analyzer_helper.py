"""The LUKS2 format analyzer helper implementation."""

from dfvfs.analyzer import analyzer
from dfvfs.analyzer import analyzer_helper
from dfvfs.analyzer import specification
from dfvfs.lib import definitions


class LUKS2AnalyzerHelper(analyzer_helper.AnalyzerHelper):
    """LUKS2 analyzer helper."""

    FORMAT_CATEGORIES = frozenset([definitions.FORMAT_CATEGORY_VOLUME_SYSTEM])

    TYPE_INDICATOR = definitions.TYPE_INDICATOR_LUKS2

    def GetFormatSpecification(self):
        """Retrieves the format specification.

        Returns:
          FormatSpecification: format specification or None if the format cannot
              be defined by a specification object.
        """
        format_specification = specification.FormatSpecification(self.type_indicator)

        # LUKS version 2 signature.
        format_specification.AddNewSignature(b"LUKS\xba\xbe\x00\x02", offset=0)

        return format_specification


analyzer.Analyzer.RegisterHelper(LUKS2AnalyzerHelper())
