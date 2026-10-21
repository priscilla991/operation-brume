"""
Chargement des sept sources de l'« Opération Brume ».

Chaque table reçoit deux colonnes ajoutées pour la traçabilité :
  - ``fichier`` : nom du fichier d'origine ;
  - ``ligne``   : numéro de ligne dans ce fichier (1 = première ligne du fichier).
    Pour un CSV, la ligne 1 est l'en-tête, la première donnée est donc la ligne 2.
    Pour le JSON (liste), « ligne » est la position de l'objet dans la liste (1, 2, ...).

Ainsi, chaque résultat peut être cité comme preuve : « proxy_web.csv, ligne 15405 ».
"""
import json
from pathlib import Path

import pandas as pd

FICHIERS = {
    "vpn": "vpn_auth.csv",
    "proxy": "proxy_web.csv",
    "firewall": "firewall.csv",
    "mail": "mail_gateway.csv",
    "inventaire": "inventaire_parc.csv",
    "ad": "ad_events.jsonl",
    "edr": "edr_alerts.json",
}


def _csv(chemin: Path, dates: bool = True) -> pd.DataFrame:
    df = pd.read_csv(chemin)
    df["ligne"] = df.index + 2          # +1 pour l'en-tête, +1 car on compte à partir de 1
    df["fichier"] = chemin.name
    if dates:
        df["horodatage"] = pd.to_datetime(df["horodatage"])
    return df


def charger(dossier) -> dict:
    """Charge les 7 sources et retourne un dictionnaire de DataFrames."""
    dossier = Path(dossier)
    manquants = [f for f in FICHIERS.values() if not (dossier / f).exists()]
    if manquants:
        raise FileNotFoundError(f"Fichiers absents dans {dossier} : {', '.join(manquants)}")

    data = {
        "vpn": _csv(dossier / FICHIERS["vpn"]),
        "proxy": _csv(dossier / FICHIERS["proxy"]),
        "firewall": _csv(dossier / FICHIERS["firewall"]),
        "mail": _csv(dossier / FICHIERS["mail"]),
        "inventaire": _csv(dossier / FICHIERS["inventaire"], dates=False),
    }

    # JSON Lines : un objet JSON par ligne
    with open(dossier / FICHIERS["ad"], encoding="utf-8") as f:
        lignes = [json.loads(l) for l in f if l.strip()]
    ad = pd.DataFrame(lignes)
    ad["ligne"] = ad.index + 1
    ad["fichier"] = FICHIERS["ad"]
    ad["horodatage"] = pd.to_datetime(ad["horodatage"])
    data["ad"] = ad

    # JSON classique : une liste d'objets
    with open(dossier / FICHIERS["edr"], encoding="utf-8") as f:
        edr = pd.DataFrame(json.load(f))
    edr["ligne"] = edr.index + 1
    edr["fichier"] = FICHIERS["edr"]
    edr["horodatage"] = pd.to_datetime(edr["horodatage"])
    data["edr"] = edr
    return data


# ---------------------------------------------------------------- correspondances inventaire
def ip_vers_machine(inventaire: pd.DataFrame) -> dict:
    """Adresse IP -> nom de machine."""
    return dict(zip(inventaire["ip"], inventaire["hostname"]))


def machine_vers_proprietaire(inventaire: pd.DataFrame) -> dict:
    """Nom de machine -> utilisateur propriétaire (vide pour les serveurs)."""
    return dict(zip(inventaire["hostname"], inventaire["proprietaire"]))


def utilisateur_vers_poste(inventaire: pd.DataFrame) -> dict:
    """Utilisateur -> nom de son poste."""
    postes = inventaire.dropna(subset=["proprietaire"])
    return dict(zip(postes["proprietaire"], postes["hostname"]))


# ---------------------------------------------------------------- affichage des preuves
def preuve(ligne: pd.Series, champs: list) -> str:
    """Formate une preuve citable : fichier, ligne et valeurs des champs utiles."""
    valeurs = " · ".join(f"{c}={ligne[c]}" for c in champs if c in ligne and pd.notna(ligne[c]))
    return f"[{ligne['fichier']}, ligne {ligne['ligne']}] {valeurs}"


def titre(texte: str) -> None:
    print("\n" + "=" * 78 + f"\n{texte}\n" + "=" * 78)
