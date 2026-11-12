"""Audit de contexte : inspection de globals() et locals()."""

from datetime import datetime, timezone
from typing import Any, Mapping


def _decrire(portee: Mapping[str, Any]) -> dict[str, str]:
    """Résume une portée : nom de variable -> type, sans les noms magiques."""
    return {
        nom: type(valeur).__name__
        for nom, valeur in sorted(portee.items(), key=lambda item: item[0])
        if isinstance(nom, str) and not nom.startswith("__")
    }


def auditer_contexte(portee_externe: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Exporte les variables chargées en mémoire pour l'audit et le débogage.

    ``globals()`` décrit le module d'audit. ``locals()`` décrit cette fonction
    au moment de l'export. ``portee_externe`` permet d'y ajouter la portée de
    l'appelant (en général ``locals()`` depuis ``main``).
    """
    horodatage = datetime.now(timezone.utc).isoformat()
    portee_demandee = {} if portee_externe is None else dict(portee_externe)
    nombre_variables_appelant = len(portee_demandee)
    variables_globales = globals()
    # Instantané pris après la création des variables locales ci-dessus.
    variables_locales = locals()

    return {
        "horodatage": horodatage,
        "nombre_variables_appelant": nombre_variables_appelant,
        "globales": _decrire(variables_globales),
        "locales": _decrire(variables_locales),
        "appelant": _decrire(portee_demandee),
    }


def formater_rapport_audit(rapport: Mapping[str, Any]) -> str:
    """Met le rapport d'audit en texte lisible pour la CLI."""

    def bloc(titre: str, variables: Mapping[str, str]) -> list[str]:
        lignes = [f"{titre} ({len(variables)}) :"]
        if not variables:
            lignes.append("  (aucune)")
            return lignes
        for nom, type_variable in variables.items():
            lignes.append(f"  - {nom}: {type_variable}")
        return lignes

    lignes = [
        f"Horodatage : {rapport['horodatage']}",
        f"Variables transmises par l'appelant : {rapport['nombre_variables_appelant']}",
    ]
    lignes.extend(bloc("Portée globale du module d'audit", rapport["globales"]))
    lignes.extend(bloc("Portée locale de l'audit", rapport["locales"]))
    lignes.extend(bloc("Portée de l'appelant", rapport["appelant"]))
    return "\n".join(lignes)
