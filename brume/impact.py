"""Niveau 4 – Mesurer l'impact : exfiltration et alertes EDR restées sans réaction."""
from __future__ import annotations

import pandas as pd

GRAVITES_FORTES = ("critique", "elevee", "moyenne")


def envois_par_hote(proxy: pd.DataFrame) -> pd.DataFrame:
    """Octets envoyés vers chaque hôte externe, avec première et dernière apparition."""
    g = proxy.groupby("host").agg(octets_envoyes=("octets_envoyes", "sum"), requetes=("ligne", "size"),
                                  utilisateurs=("login", "nunique"), premiere=("horodatage", "min"),
                                  derniere=("horodatage", "max"))
    g["mo"] = (g["octets_envoyes"] / 1e6).round(1)
    mediane = g["octets_envoyes"].median()
    g["x_mediane"] = (g["octets_envoyes"] / mediane).round(0)
    return g.sort_values("octets_envoyes", ascending=False)


def exfiltration(proxy: pd.DataFrame, hote: str) -> dict:
    """Détail des envois vers l'hôte d'exfiltration : jour, plage horaire, compte, poste, volume."""
    e = proxy[proxy["host"] == hote].sort_values("horodatage")
    octets = int(e["octets_envoyes"].sum())
    return {
        "hote": hote, "requetes": len(e), "octets": octets,
        "go": round(octets / 1e9, 2), "gio": round(octets / 2**30, 2),
        "debut": e["horodatage"].min(), "fin": e["horodatage"].max(),
        "comptes": e["login"].unique().tolist(), "postes": e["ip_source"].unique().tolist(),
        "methodes": e["methode"].value_counts().to_dict(), "urls": e["url"].unique().tolist(),
        "lignes": f"{e['ligne'].min()}–{e['ligne'].max()}", "detail": e,
    }


def alertes_edr(edr: pd.DataFrame) -> dict:
    """Alertes importantes restées ouvertes, et contexte qui explique pourquoi elles sont passées inaperçues."""
    fortes = edr[edr["gravite"].isin(GRAVITES_FORTES)].sort_values("horodatage").copy()
    fortes["nuit_ou_week_end"] = (~fortes["horodatage"].dt.hour.between(7, 19)) | (fortes["horodatage"].dt.dayofweek >= 5)
    return {
        "ouvertes": fortes[fortes["statut"] == "ouvert"],
        "total": len(edr),
        "faux_positifs": int((edr["statut"] == "clos_faux_positif").sum()),
        "par_gravite": edr.groupby(["gravite", "statut"]).size().unstack(fill_value=0),
    }


def acces_serveurs(ad: pd.DataFrame, fw: pd.DataFrame, compte: str, ip_interne: str | None) -> pd.DataFrame:
    """Serveurs touchés : connexions AD du compte de l'attaquant et flux RDP de l'adresse VPN de l'attaquant."""
    a = ad[(ad["utilisateur"] == compte) & (ad["event_id"] == 4624)][["horodatage", "machine_cible", "fichier", "ligne"]]
    a = a.rename(columns={"machine_cible": "cible"})
    lignes = [a.assign(source="AD (connexion du compte)")]
    if ip_interne:
        f = fw[(fw["ip_source"] == ip_interne) & (fw["action"] == "autorise") & (fw["octets"] > 1000)]
        f = f[["horodatage", "ip_dest", "fichier", "ligne"]].rename(columns={"ip_dest": "cible"})
        lignes.append(f.assign(source="Pare-feu (session RDP)"))
    return pd.concat(lignes).sort_values("horodatage")
