from collections import defaultdict, deque
from itertools import islice
from typing import Iterable

from .models import Finding, LogRecord


def ips_en_erreur(logs: Iterable[LogRecord]) -> set[str]:
    return {log.ip for log in logs if log.level in {"ERROR", "CRITICAL"}}


def comparer_blacklist(
    ips_actives: set[str],
    blacklist: frozenset[str],
) -> dict[str, set[str]]:
    blacklist_immuable = frozenset(blacklist)
    return {
        "union": ips_actives | blacklist_immuable,
        "intersection": ips_actives & blacklist_immuable,
        "difference": ips_actives - blacklist_immuable,
        "difference_symetrique": ips_actives ^ blacklist_immuable,
    }


def compter_occurrences(
    logs: Iterable[LogRecord],
) -> tuple[defaultdict[str, int], defaultdict[str, int]]:
    par_niveau: defaultdict[str, int] = defaultdict(int)
    par_utilisateur: defaultdict[str, int] = defaultdict(int)

    for log in logs:
        par_niveau[log.level] += 1
        par_utilisateur[log.user] += 1

    return par_niveau, par_utilisateur


def detecter_force_brute(
    logs: Iterable[LogRecord],
    seuil: int = 3,
    taille_cycle: int = 20,
) -> list[Finding]:
    if seuil < 1 or taille_cycle < 1:
        raise ValueError("seuil et taille_cycle doivent être >= 1.")

    historique: defaultdict[tuple[str, str], deque[str]] = defaultdict(
        lambda: deque(maxlen=seuil)
    )
    deja_alertee: defaultdict[tuple[str, str], bool] = defaultdict(bool)
    alertes: list[Finding] = []

    flux = iter(logs)
    lot = list(islice(flux, taille_cycle))

    while lot:
        for log in lot:
            if log.event not in {"LOGIN_SUCCESS", "LOGIN_FAILED"}:
                continue

            cle = (log.ip, log.user)
            historique[cle].append(log.event)

            if log.event == "LOGIN_SUCCESS":
                deja_alertee[cle] = False
                continue

            if len(historique[cle]) < seuil or deja_alertee[cle]:
                continue

            for evenement in historique[cle]:
                if evenement != "LOGIN_FAILED":
                    break
            else:
                alertes.append(
                    Finding(
                        timestamp=log.timestamp,
                        ip=log.ip,
                        user=log.user,
                    )
                )
                deja_alertee[cle] = True

        lot = list(islice(flux, taille_cycle))

    return alertes
