"""Moteur de règles : les fonctions de sécurité sont des objets de première classe."""

from typing import Any, Callable, Iterable, Iterator

from .analysis import detecter_force_brute
from .models import Finding, LogRecord

# Une règle reçoit les logs déjà parsés et la configuration dynamique.
SecurityRule = Callable[..., Iterable[Finding]]


class SecurityRuleError(TypeError):
    """Une règle fournie au moteur n'est pas utilisable."""


def apply_security_rules(*rules: SecurityRule, **config: Any) -> list[Finding]:
    """Applique un nombre variable de règles, configurées via **kwargs.

    Les règles sont passées en *args et appelées comme des fonctions ordinaires.
    La configuration (seuil, blacklist, événements sensibles, etc.) arrive dans
    **kwargs. Le flux de logs est obligatoire : ``logs=...``.
    """
    if not rules:
        raise SecurityRuleError("Aucune règle de sécurité fournie.")
    if "logs" not in config:
        raise SecurityRuleError("Le paramètre 'logs' est obligatoire.")

    logs = config.pop("logs")
    try:
        enregistrements = tuple(logs)
    except TypeError as erreur:
        raise SecurityRuleError("'logs' doit être un itérable de LogRecord.") from erreur

    resultats: list[Finding] = []
    for regle in rules:
        if not callable(regle):
            raise SecurityRuleError(f"Règle non appelable : {regle!r}")

        produit = regle(enregistrements, **config)
        try:
            resultats.extend(produit)
        except TypeError as erreur:
            nom = getattr(regle, "__name__", repr(regle))
            raise SecurityRuleError(
                f"La règle {nom} doit renvoyer un itérable de Finding."
            ) from erreur

    return resultats


def regle_force_brute(
    logs: Iterable[LogRecord],
    **config: Any,
) -> Iterator[Finding]:
    """Signale X échecs de connexion consécutifs (seuil via kwargs)."""
    seuil = int(config.get("seuil", 3))
    taille_cycle = int(config.get("taille_cycle", 50))

    for alerte in detecter_force_brute(logs, seuil=seuil, taille_cycle=taille_cycle):
        yield Finding(
            timestamp=alerte.timestamp,
            ip=alerte.ip,
            user=alerte.user,
            rule="force_brute",
            detail=f"{seuil} échecs de connexion consécutifs",
        )


def regle_ip_blacklist(
    logs: Iterable[LogRecord],
    **config: Any,
) -> Iterator[Finding]:
    """Signale chaque log dont l'IP appartient à la blacklist (frozenset)."""
    blacklist = frozenset(config.get("blacklist", ()))

    for log in logs:
        if log.ip not in blacklist:
            continue
        yield Finding(
            timestamp=log.timestamp,
            ip=log.ip,
            user=log.user,
            rule="blacklist",
            detail="IP présente dans la blacklist",
        )


def regle_evenements_sensibles(
    logs: Iterable[LogRecord],
    **config: Any,
) -> Iterator[Finding]:
    """Signale les événements listés dans la configuration."""
    evenements = set(config.get("evenements_sensibles", {"FIREWALL_BLOCK"}))

    for log in logs:
        if log.event not in evenements:
            continue
        yield Finding(
            timestamp=log.timestamp,
            ip=log.ip,
            user=log.user,
            rule="evenement_sensible",
            detail=log.event,
        )
