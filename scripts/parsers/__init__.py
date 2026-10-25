"""Modular feed parsers for PHP2Shell IoC collection."""

from __future__ import annotations

from scripts.parsers.base_parser import BaseParser
from scripts.parsers.fortiguard_parser import FortiGuardParser
from scripts.parsers.csv_parser import CsvParser
from scripts.parsers.generic_parser import GenericParser

PARSER_REGISTRY: dict[str, type[BaseParser]] = {
    "fortiguard": FortiGuardParser,
    "csv": CsvParser,
    "generic": GenericParser,
}


def get_parser(name: str) -> BaseParser:
    """Instantiate a parser by registered name."""
    parser_cls = PARSER_REGISTRY.get(name.lower())
    if not parser_cls:
        raise ValueError(f"Unknown parser: '{name}'. Available: {list(PARSER_REGISTRY.keys())}")
    return parser_cls()


__all__ = [
    "BaseParser",
    "FortiGuardParser",
    "CsvParser",
    "GenericParser",
    "PARSER_REGISTRY",
    "get_parser",
]
