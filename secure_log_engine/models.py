"""Modèles communs : une fiche de log et une fiche d'alerte.

Le fichier ne réalise aucun traitement : il définit seulement les données.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any

# Un tuple ne peut pas être modifié après sa création.
Connection = tuple[str, int, str]  # (IP, port, protocole)
Payload = str | dict[str, Any] | tuple


@dataclass(frozen=True)
class LogRecord:
    """Informations extraites d'une ligne de log."""

    timestamp: datetime
    level: str
    ip: str
    user: str
    event: str
    payload: Payload
    connection: Connection | None = None


@dataclass(frozen=True)
class Finding:
    """Alerte produite par l'analyse ou par une règle de sécurité."""

    timestamp: datetime
    ip: str
    user: str
    rule: str = ""
    detail: str = ""
