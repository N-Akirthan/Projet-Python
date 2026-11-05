"""Transformer les lignes reçues en données structurées et vérifiées.

Trois formats acceptés : JSON, texte séparé par |, tuple Python.
"""

import ast
import ipaddress
import json
from dataclasses import replace
from datetime import datetime, timezone

from .models import LogRecord

NIVEAUX_VALIDES = {"INFO", "WARNING", "ERROR", "CRITICAL"}
TAILLE_MAX_LIGNE = 1_000_000


class LogParseError(ValueError):
    """Erreur lorsqu'une ligne de log est incorrecte."""


def read_line_fields(ligne: str) -> dict:
    """Lire une ligne et renvoyer un dictionnaire de ses champs."""
    ligne = ligne.strip()

    try:
        if ligne.startswith(("{", "[")):
            contenu = json.loads(ligne)
        elif ligne.startswith("("):
            contenu = ast.literal_eval(ligne)  # Plus sûr que eval().
        else:
            contenu = ligne
    except (ValueError, SyntaxError, RecursionError) as erreur:
        raise LogParseError("Format de log incorrect") from erreur

    # match-case permet de reconnaître le type de données reçu.
    match contenu:
        case dict():
            return contenu
        case (list() | tuple()) if len(contenu) == 6:
            date, niveau, ip, utilisateur, evenement, payload = contenu
        case str():
            champs = contenu.split("|", 5)
            if len(champs) != 6:
                raise LogParseError("La ligne doit contenir 6 champs séparés par |")
            date, niveau, ip, utilisateur, evenement, payload = champs

            # Le dernier champ peut être du JSON ou du texte simple.
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                pass
        case _:
            raise LogParseError("Type de log non reconnu")

    return {
        "timestamp": date,
        "level": niveau,
        "ip": ip,
        "user": utilisateur,
        "event": evenement,
        "payload": payload,
    }


def read_date(texte: str) -> datetime:
    """Lire une date ISO et utiliser le fuseau UTC."""
    if not isinstance(texte, str):
        raise LogParseError("Date non valide")

    try:
        date = datetime.fromisoformat(texte.strip().replace("Z", "+00:00"))
    except ValueError as erreur:
        raise LogParseError("Date non valide") from erreur

    if date.tzinfo is None:
        date = date.replace(tzinfo=timezone.utc)
    return date.astimezone(timezone.utc)


def read_connection(valeur):
    """Convertir une connexion [IP, port, protocole] en tuple immuable."""
    if valeur is None:
        return None
    if not isinstance(valeur, (list, tuple)) or len(valeur) != 3:
        raise LogParseError("Connexion invalide")

    ip, port, protocole = valeur
    if not isinstance(ip, str) or not isinstance(port, int):
        raise LogParseError("IP ou port incorrect")
    if not isinstance(protocole, str) or not 0 <= port <= 65535:
        raise LogParseError("Port ou protocole incorrect")

    try:
        ipaddress.ip_address(ip.strip())
    except ValueError as erreur:
        raise LogParseError("IP de connexion incorrecte") from erreur

    return (ip.strip(), port, protocole.strip().upper())


def parse_log_line(ligne: str) -> LogRecord:
    """Convertir une ligne en fiche LogRecord."""
    if len(ligne) > TAILLE_MAX_LIGNE:
        raise LogParseError("Ligne trop longue")

    champs = read_line_fields(ligne)
    obligatoires = ["timestamp", "level", "ip", "user", "event"]

    for nom in obligatoires:
        if nom not in champs:
            raise LogParseError(f"Champ manquant : {nom}")

    for nom in ["level", "ip", "user", "event"]:
        if not isinstance(champs[nom], str):
            raise LogParseError(f"Le champ {nom} doit être du texte")

    payload = champs.get("payload", "")
    if isinstance(payload, list):
        payload = tuple(payload)
    if payload is None:
        payload = ""
    if not isinstance(payload, (str, dict, tuple)):
        payload = str(payload)

    return LogRecord(
        timestamp=read_date(champs["timestamp"]),
        level=champs["level"],
        ip=champs["ip"],
        user=champs["user"],
        event=champs["event"],
        payload=payload,
        connection=read_connection(champs.get("connection")),
    )


def normalize_record(log: LogRecord) -> LogRecord:
    """Enlever les espaces et mettre les valeurs importantes en majuscules."""
    payload = log.payload
    if isinstance(payload, str):
        payload = payload.strip()
    elif isinstance(payload, dict):
        payload = {str(cle).strip(): valeur for cle, valeur in payload.items()}

    return replace(
        log,
        level=log.level.strip().upper(),
        ip=log.ip.strip(),
        user=log.user.strip(),
        event=log.event.strip().upper(),
        payload=payload,
    )


def valid_record(log: LogRecord) -> bool:
    """Vérifier le niveau, l'utilisateur, l'événement et l'adresse IP."""
    if log.level not in NIVEAUX_VALIDES:
        return False
    if not log.user or not log.event:
        return False

    try:
        ipaddress.ip_address(log.ip)
    except ValueError:
        return False
    return True


def route_payload(payload) -> str:
    """Classer le contenu d'un log selon son format (match-case)."""
    match payload:
        case {"level": "ERROR", "code": code}:
            return f"JSON_ERREUR_{code}"
        case dict():
            return "DICTIONNAIRE_JSON"
        case (str(), int(), str() as protocole):
            return f"TUPLE_CONNEXION_{protocole.upper()}"
        case tuple():
            return "TUPLE_AUTRE"
        case str():
            return "CHAINE_BRUTE"
        case _:
            return "AUTRE"
