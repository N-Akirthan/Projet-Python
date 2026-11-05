"""Tests de la partie 1 seulement (bibliothèque standard unittest)."""

import json
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

from secure_log_engine.ingestion import iter_file_lines, iter_sources, simulate_logs
from secure_log_engine.parsing import (
    LogParseError,
    normalize_record,
    parse_log_line,
    read_line_fields,
    route_payload,
    valid_record,
)

DOSSIER = Path(__file__).resolve().parents[1]


class IngestionTests(unittest.TestCase):
    def test_lire_plusieurs_fichiers(self):
        with tempfile.TemporaryDirectory() as dossier:
            fichier_1 = Path(dossier) / "un.log"
            fichier_2 = Path(dossier) / "deux.log"
            fichier_1.write_text("ligne 1\nligne 2\n", encoding="utf-8")
            fichier_2.write_text("ligne 3\n", encoding="utf-8")
            self.assertEqual(list(iter_file_lines(fichier_1)), ["ligne 1", "ligne 2"])
            self.assertEqual(list(iter_sources([fichier_1, fichier_2])),
                             ["ligne 1", "ligne 2", "ligne 3"])

    def test_la_simulation_ne_construit_pas_de_liste(self):
        generateur = simulate_logs(100)
        self.assertTrue(hasattr(generateur, "__next__"))
        self.assertEqual(sum(1 for _ in generateur), 100)
        with self.assertRaises(ValueError):
            list(simulate_logs(-1))


class ParsingTests(unittest.TestCase):
    def test_json_et_normalisation(self):
        ligne = json.dumps({
            "timestamp": "2026-11-01T08:00:00Z", "level": "error",
            "ip": " 192.0.2.1 ", "user": " Alice ", "event": " login_failed ",
            "payload": {"raison": "mot de passe"},
            "connection": ["192.0.2.1", 443, "tcp"],
        })
        champs = read_line_fields(ligne)
        self.assertIsInstance(champs, dict)
        log = normalize_record(parse_log_line(ligne))
        self.assertEqual(log.level, "ERROR")
        self.assertEqual(log.ip, "192.0.2.1")
        self.assertEqual(log.event, "LOGIN_FAILED")
        self.assertEqual(log.connection, ("192.0.2.1", 443, "TCP"))
        self.assertTrue(valid_record(log))
        with self.assertRaises(FrozenInstanceError):
            log.connection = None

    def test_texte_avec_barres(self):
        ligne = '2026-11-01T08:00:00Z|ERROR|192.0.2.2|bob|API_ERROR|{"level":"ERROR","code":403}'
        log = parse_log_line(ligne)
        self.assertEqual(route_payload(log.payload), "JSON_ERREUR_403")

    def test_tuple_python(self):
        ligne = "('2026-11-01T08:00:00Z','info','192.0.2.8','bob','CONNECTION',('192.0.2.8',443,'TCP'))"
        log = normalize_record(parse_log_line(ligne))
        self.assertEqual(route_payload(log.payload), "TUPLE_CONNEXION_TCP")

    def test_lignes_invalides(self):
        with self.assertRaises(LogParseError):
            parse_log_line("LIGNE_INVALIDE")
        with self.assertRaises(LogParseError):
            parse_log_line("a" * 1_000_001)

        log = parse_log_line(json.dumps({
            "timestamp": "2026-11-01T08:00:00Z", "level": "ERROR",
            "ip": "pas-une-ip", "user": "alice", "event": "LOGIN_FAILED"}))
        self.assertFalse(valid_record(log))

    def test_donnees_du_projet(self):
        lignes = iter_sources([DOSSIER / "data" / "sample_1.log",
                               DOSSIER / "data" / "sample_2.log"])
        valides = invalides = vides = 0
        for ligne in lignes:
            if not ligne.strip():
                vides += 1
                continue
            try:
                log = normalize_record(parse_log_line(ligne))
                if valid_record(log):
                    valides += 1
                else:
                    invalides += 1
            except LogParseError:
                invalides += 1
        self.assertEqual((valides, invalides, vides), (14, 2, 1))


if __name__ == "__main__":
    unittest.main()
