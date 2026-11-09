# Engine de Traitement et d'Analyse de Flux de Données Sécurisé en Temps Réel

Plateforme en ligne de commande (CLI) d'ingestion et d'analyse de journaux de logs volumineux, développée en **Python 3.10+**.

---

## 1. Objectif & Contraintes Mémoire

L'application traite des données de logs sans charger l'intégralité des fichiers en mémoire vive (RAM) :
* **Lecture à la demande** : Utilisation de générateurs Python (`yield` et `yield from`) pour lire ligne par ligne.
* **Architecture modulaire** : Séparation propre en package Python (`secure_log_engine`) et point d'entrée principal (`main.py`).

---

## 2. Structure des Fichiers

```text
Projet-Python/
│
├── main.py                     # Point d'entrée principal pilotant le pipeline
├── demo_personne1.py           # Script de démonstration autonome
├── requirements.txt            # Dépendances pour l'environnement virtuel (venv)
├── pyproject.toml              # Métadonnées du package Python
├── README.md                   # Documentation du projet
│
├── secure_log_engine/          # Package Python principal
│   ├── __init__.py             # Exports du package
│   ├── ingestion.py            # Générateurs mémoire (yield / yield from)
│   ├── models.py               # Structures de données (LogRecord, tuples)
│   └── parsing.py              # Découpage, normalisation et validation des lignes
│
├── data/                       # Fichiers de logs de test
│   ├── sample_1.log
│   └── sample_2.log
│
└── tests/                      # Tests unitaires automatisés
    └── test_partie1.py
```

---

## 3. Environnement Virtuel & Installation

Conformément aux consignes, le projet fonctionne dans un environnement virtuel isolé (`venv`).

### Création et activation de l'environnement virtuel

**Sous Windows (PowerShell) :**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Sous Linux / macOS :**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Dépendances

Le Module 1 utilise exclusivement la bibliothèque standard de Python 3.10+. Le fichier `requirements.txt` est prêt pour `pip freeze` :
```bash
pip install -r requirements.txt
```

---

## 4. Utilisation du Programme (`main.py`)

### A. Lecture normale des fichiers de logs
```powershell
python main.py
```

### B. Simulation d'un flux de logs sans fichier
Pour simuler par exemple 50 logs générés en direct :
```powershell
python main.py --simulate 50
```

---

## 5. Lancer les Tests

Pour vérifier que tout fonctionne :
```powershell
python -m unittest discover tests
```
