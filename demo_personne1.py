"""Démonstration autonome : seulement l'ingestion et le parsing."""

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

DOSSIER = Path(__file__).resolve().parent


def afficher_logs(lignes):
    """Lire, vérifier et afficher les 5 premiers logs valides."""
    total = 0
    vides = 0
    invalides = 0
    valides = 0

    for ligne in lignes:
        total += 1

        if not ligne.strip():
            vides += 1
            continue

        try:
            log = parse_log_line(ligne)
            log = normalize_record(log)
        except LogParseError:
            invalides += 1
            continue

        if not valid_record(log):
            invalides += 1
            continue

        valides += 1
        if valides <= 5:
            print(f"{log.timestamp} | {log.level} | {log.ip} | {log.user} | {log.event}")
            print(f"  Type du payload : {route_payload(log.payload)}")

    print("\n--- Résultat de la partie 1 ---")
    print(f"Lignes reçues : {total}")
    print(f"Lignes valides : {valides}")
    print(f"Lignes vides : {vides}")
    print(f"Lignes invalides : {invalides}")
    print("Aucune analyse d'attaque n'est réalisée dans cette partie.")


def main():
    parser = argparse.ArgumentParser(description="Tester la partie 1 : logs et parsing")
    parser.add_argument("--simulate", type=int, help="Nombre de logs à simuler")
    arguments = parser.parse_args()

    if arguments.simulate is not None:
        if arguments.simulate < 0:
            parser.error("--simulate doit être positif")
        lignes = simulate_logs(arguments.simulate)
    else:
        fichiers = [DOSSIER / "data" / "sample_1.log",
                    DOSSIER / "data" / "sample_2.log"]
        lignes = iter_sources(fichiers)

    try:
        afficher_logs(lignes)
    except OSError as erreur:
        parser.error(f"Impossible de lire les fichiers : {erreur}")


if __name__ == "__main__":
    main()
