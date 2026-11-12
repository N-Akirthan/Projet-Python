"""Package secure_log_engine.

Engine modulaire de traitement, de filtrage et d'analyse de flux de logs
en temps réel sans saturation de la mémoire vive (RAM).
"""

from .audit import auditer_contexte, formater_rapport_audit
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

from .analysis import (
    comparer_blacklist,
    compter_occurrences,
    detecter_force_brute,
    ips_en_erreur,
)
from .rules import (
    SecurityRuleError,
    apply_security_rules,
    regle_evenements_sensibles,
    regle_force_brute,
    regle_ip_blacklist,
)

__all__ = [
    "Connection",
    "Finding",
    "LogRecord",
    "Payload",
    "SecurityRuleError",
    "apply_security_rules",
    "auditer_contexte",
    "comparer_blacklist",
    "compter_occurrences",
    "detecter_force_brute",
    "formater_rapport_audit",
    "ips_en_erreur",
    "regle_evenements_sensibles",
    "regle_force_brute",
    "regle_ip_blacklist",
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
