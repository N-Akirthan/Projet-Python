import argparse
from collections import defaultdict
from pathlib import Path

from secure_log_engine.analysis import comparer_blacklist, detecter_force_brute
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
BLACKLIST = frozenset({"203.0.113.66", "198.51.100.99"})


def traiter_les_logs(lignes):
    """Lit les lignes de logs une par une et affiche les 5 premiers valides."""
    total = 0
    valides = 0
    invalides = 0
    ips_actives = set()
    ips_erreur = set()
    par_niveau = defaultdict(int)

    print("--- Démarrage de la lecture des logs ---")

    def flux_valide():
        nonlocal total, valides, invalides
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
            ips_actives.add(log.ip)
            par_niveau[log.level] += 1
            if log.level in {"ERROR", "CRITICAL"}:
                ips_erreur.add(log.ip)

            if valides <= 10:
                type_payload = route_payload(log.payload)
                print(f"[{log.level}] {log.timestamp} | IP: {log.ip} | User: {log.user} | Event: {log.event} ({type_payload})")

            yield log

    alertes = detecter_force_brute(flux_valide())
    ensembles = comparer_blacklist(ips_actives, BLACKLIST)

    # Résumé final
    print("\n--- Bilan du traitement ---")
    print(f"Total de lignes lues : {total}")
    print(f"Logs valides : {valides}")
    print(f"Logs rejetés (invalides) : {invalides}")
    print(f"Répartition par niveau : {dict(par_niveau)}")

    # Bilan de sécurité (Module 3)
    print("\n--- Bilan de sécurité ---")
    print(f"IP uniques en erreur : {ips_erreur if ips_erreur else 'Aucune'}")

    if not alertes:
        print("Aucune alerte détectée.")
    else:
        print(f"Alertes force brute ({len(alertes)}) :")
    for alerte in alertes:
        print(f"{alerte.timestamp} | IP: {alerte.ip} | User: {alerte.user}")
    print("\nOpération d'ensemble mathématique:\n")
    print(f"IP  |  blacklistées  : {ensembles['union'] or 'Aucune'}")
    print(f"IP  &  blacklistées  : {ensembles['intersection'] or 'Aucune'}")
    print(f"IP  ^  blacklistées  : {ensembles['difference_symetrique'] or 'Aucune'}")
    print(f"IP  -  blacklistées  : {ensembles['difference'] or 'Aucune'}")



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
