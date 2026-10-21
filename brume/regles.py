"""
Niveau 5 – Règles de détection proposées, testées sur les trois semaines de journaux.

Chaque règle renvoie les événements qu'elle aurait levés. On mesure ainsi :
  - si elle aurait détecté l'attaque, et à quelle date ;
  - combien d'alertes elle aurait produites au total (le « bruit » pour le SOC).
"""
from __future__ import annotations

import pandas as pd

from . import entree, progression


def r1_courriel_piege(data):
    m = entree.mails_suspects(data["mail"])
    m = m[(m["imite"].notna()) | (m["double_extension"])]
    return m.assign(regle="R1 Courriel livré : domaine sosie ou double extension")


def r2_vpn_geo(data):
    v = entree.vpn_anormal(data["vpn"])
    v = v[v["resultat"] == "succes"]
    return v.assign(regle="R2 VPN réussi hors de France ou IP à pays multiples")


def r3_ip_inconnue(data):
    inv_ips = set(data["inventaire"]["ip"])
    fw = data["firewall"]
    f = fw[fw["ip_source"].str.startswith("10.") & ~fw["ip_source"].isin(inv_ips)]
    # une alerte par adresse et par jour
    f = f.sort_values("horodatage").groupby([f["ip_source"], f["horodatage"].dt.date]).head(1)
    return f.assign(regle="R3 Adresse interne absente de l'inventaire")


def r4_balayage(data):
    b = progression.detecter_balayage(data["firewall"])
    return b.rename(columns={"tranche": "horodatage"}).assign(regle="R4 Balayage (≥ 10 couples IP:port en 1 min)")


def r5_rafale_puis_succes(data):
    r = progression.rafales_echecs(data["ad"])
    r = r[r["succes_ensuite"]].rename(columns={"heure_succes": "horodatage"})
    return r.assign(regle="R5 Rafale d'échecs suivie d'un succès")


def r6_admin_hors_heures(data):
    c = progression.creations_et_ajouts_admin(data["ad"])
    c = c[c["groupe_admin"] | (c["hors_heures"] & (c["event_id"] == 4720))]
    return c.assign(regle="R6 Ajout à un groupe admin ou création de compte la nuit")


def r7_envoi_massif(data, seuil_mo: float = 100):
    p = data["proxy"]
    j = (p.assign(jour=p["horodatage"].dt.date)
         .groupby(["jour", "host", "login"])
         .agg(octets=("octets_envoyes", "sum"), horodatage=("horodatage", "min"), ligne=("ligne", "min"))
         .reset_index())
    j = j[j["octets"] >= seuil_mo * 1e6]
    return j.assign(regle=f"R7 Envoi sortant ≥ {seuil_mo:.0f} Mo par jour vers un même hôte")


REGLES = [r1_courriel_piege, r2_vpn_geo, r3_ip_inconnue, r4_balayage, r5_rafale_puis_succes,
          r6_admin_hors_heures, r7_envoi_massif]


def evaluer(data, debut_sabotage: pd.Timestamp) -> pd.DataFrame:
    """Pour chaque règle : nombre d'alertes sur la période, première alerte, avance sur le sabotage."""
    lignes = []
    for regle in REGLES:
        hits = regle(data)
        nom = hits["regle"].iloc[0] if len(hits) else regle.__name__
        premiere = hits["horodatage"].min() if len(hits) else pd.NaT
        avance = (debut_sabotage - premiere) if pd.notna(premiere) else pd.NaT
        lignes.append({"regle": nom, "alertes_sur_3_semaines": len(hits), "premiere_alerte": premiere,
                       "avance_sur_sabotage": avance})
    return pd.DataFrame(lignes)
