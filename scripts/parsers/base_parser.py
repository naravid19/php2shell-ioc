"""Abstract Base Parser for PHP2Shell IoC feeds."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseParser(ABC):
    """Abstract base class for source-specific indicator parsers."""

    @abstractmethod
    def parse(self, content: str, config: dict[str, Any]) -> list[dict[str, str]]:
        """Parse raw content string and return normalized indicator dictionaries.

        Args:
            content: Raw feed content (HTML, CSV, text, JSON).
            config: Source configuration parameters and metadata defaults.

        Returns:
            List of normalized indicator records.
        """
        raise NotImplementedError
