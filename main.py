"""Point d'entrée principal du projet (Module 1 : Ingestion et Parsing)."""

import argparse
from pathlib import Path

from secure_log_engine.ingestion import iter_sources, simulate_logs
from secure_log_engine.parsing import (
    LogParseError,
    normalize_record,
    parse_log_line,
    route_payload,
    valid_record,
)

# Dossier où se trouve ce fichier main.py
DOSSIER = Path(__file__).resolve().parent


def traiter_les_logs(lignes):
    """Lit les lignes de logs une par une et affiche les 5 premiers valides."""
    total = 0
    valides = 0
    invalides = 0

    print("--- Démarrage de la lecture des logs ---")

    # On parcourt les logs un par un (grâce aux générateurs, la RAM reste vide)
    for ligne in lignes:
        total += 1

        # Ignorer les lignes vides
        if not ligne.strip():
            continue

        try:
            # 1. On parse la ligne et on la nettoie
            log = parse_log_line(ligne)
            log = normalize_record(log)
        except LogParseError:
            invalides += 1
            continue

        # 2. On vérifie si l'IP et les champs sont corrects
        if not valid_record(log):
            invalides += 1
            continue

        # 3. Le log est valide !
        valides += 1
        if valides <= 5:
            type_payload = route_payload(log.payload)
            print(f"[{log.level}] {log.timestamp} | IP: {log.ip} | User: {log.user} | Event: {log.event} ({type_payload})")

    # Résumé final
    print("\n--- Bilan du traitement ---")
    print(f"Total de lignes lues : {total}")
    print(f"Logs valides : {valides}")
    print(f"Logs rejetés (invalides) : {invalides}")


def main():
    """Gère les options en ligne de commande (CLI)."""
    parser = argparse.ArgumentParser(description="Moteur de traitement de logs en temps réel")
    parser.add_argument("--simulate", type=int, help="Simuler N logs sans fichier")
    args = parser.parse_args()

    # Si l'utilisateur a écrit --simulate 50, on simule des logs
    if args.simulate is not None:
        print(f"Mode simulation : création de {args.simulate} logs...")
        flux_de_logs = simulate_logs(args.simulate)
    else:
        # Sinon, par défaut on lit les fichiers du dossier data/
        fichiers = [
            DOSSIER / "data" / "sample_1.log",
            DOSSIER / "data" / "sample_2.log",
        ]
        print("Mode fichiers : lecture de sample_1.log et sample_2.log...")
        flux_de_logs = iter_sources(fichiers)

    # On lance le traitement
    traiter_les_logs(flux_de_logs)


if __name__ == "__main__":
    main()
