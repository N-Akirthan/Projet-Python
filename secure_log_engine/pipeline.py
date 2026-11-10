from .parsing import normalize_record,valid_record

def filtre_lignes_vides(flux_lignes):
    return filter(lambda ligne: ligne.strip() != "",flux_lignes)

def filtre_logs_valide(flux_logs):
    return filter(lambda log: valid_record(log),flux_logs)

def normaliser_un_log(log):
    log = normalize_record(log)
    return log

def normaliser_flux(flux_logs):
    return map(normaliser_un_log,flux_logs)

def formater_log(log):
    return f"[{log.level}] {log.timestamp} | {log.ip} | {log.user} | {log.event}"

def router_payload(payload):
    match payload:
        case {"level": "ERROR", "code": code}:
            return f"JSON_ERREUR_{code}"
        case dict():
            return "DICTIONNAIRE_JSON"
        case (str(), int(), str() as protocole):
            return f"TUPLE_CONNEXION_{protocole.upper()}"
        case str():
            return "CHAINE_BRUTE"
        case _:
            return "AUTRE"