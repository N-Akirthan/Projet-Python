"""Lire des logs un par un, sans charger tout le fichier en mémoire."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Iterator


def iter_file_lines(path: Path) -> Iterator[str]:
    """Lire un fichier ligne par ligne grâce à yield."""
    with Path(path).open("r", encoding="utf-8") as fichier:
        for ligne in fichier:
            yield ligne.rstrip("\r\n")


def iter_sources(paths: Iterable[Path]) -> Iterator[str]:
    """Lire plusieurs fichiers successivement grâce à yield from."""
    for path in paths:
        yield from iter_file_lines(path)


def simulate_logs(count: int) -> Iterator[str]:
    """Créer des logs de test au fur et à mesure, sans grande liste."""
    if count < 0:
        raise ValueError("Le nombre de logs ne peut pas être négatif.")

    debut = datetime(2026, 11, 1, 8, tzinfo=timezone.utc)

    for numero in range(count):
        ip_numero = numero % 200 + 1
        ip = f"192.0.2.{ip_numero}"
        evenement = "LOGIN_SUCCESS" if numero % 23 == 0 else "LOGIN_FAILED"
        niveau = "INFO" if evenement == "LOGIN_SUCCESS" else "WARNING"

        log = {
            "timestamp": (debut + timedelta(seconds=numero)).isoformat(),
            "level": niveau,
            "ip": ip,
            "user": f"user_{ip_numero}",
            "event": evenement,
            "payload": {"code": "AUTH", "source": "simulation"},
            "connection": [ip, 443, "TCP"],
        }
        yield json.dumps(log, ensure_ascii=False)
