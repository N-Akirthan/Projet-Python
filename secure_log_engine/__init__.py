"""Package secure_log_engine.

Engine modulaire de traitement, de filtrage et d'analyse de flux de logs
en temps réel sans saturation de la mémoire vive (RAM).
"""

from .ingestion import iter_file_lines, iter_sources, simulate_logs
from .models import Connection, Finding, LogRecord, Payload
from .parsing import (
    LogParseError,
    iter_valid_logs,
    normalize_record,
    parse_log_line,
    read_connection,
    read_date,
    read_line_fields,
    route_payload,
    valid_record,
)

__all__ = [
    "Connection",
    "Finding",
    "LogRecord",
    "Payload",
    "iter_file_lines",
    "iter_sources",
    "simulate_logs",
    "LogParseError",
    "iter_valid_logs",
    "normalize_record",
    "parse_log_line",
    "read_connection",
    "read_date",
    "read_line_fields",
    "route_payload",
    "valid_record",
]
