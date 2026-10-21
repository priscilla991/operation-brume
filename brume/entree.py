"""Niveau 2 – Trouver le point d'entrée : courriel piégé, hameçonnage, connexion VPN de l'attaquant."""
from __future__ import annotations

from difflib import SequenceMatcher
from urllib.parse import urlparse

import pandas as pd

SIMILARITE_SOSIE = 0.85      # au-delà, un domaine est considéré comme « sosie » d'un domaine connu
FENETRE_CLIC = pd.Timedelta(hours=4)


def domaine(adresse: str) -> str:
    return str(adresse).split("@")[-1].lower()


def domaines_connus(mail: pd.DataFrame, minimum: int = 50) -> list:
    """Domaines d'expéditeurs fréquents et non spam : la « normale » de la messagerie."""
    livres = mail[mail["verdict"] == "livre"]
    freq = livres["expediteur"].map(domaine).value_counts()
    return freq[freq >= minimum].index.tolist()


def sosie(dom: str, connus: list) -> str | None:
    """Retourne le domaine légitime imité, si ``dom`` lui ressemble sans être identique."""
    for c in connus:
        if dom != c and SequenceMatcher(None, dom, c).ratio() >= SIMILARITE_SOSIE:
            return c
    return None


def mails_suspects(mail: pd.DataFrame) -> pd.DataFrame:
    """Courriels LIVRÉS présentant des signaux de piège, triés par nombre de signaux puis score."""
    connus = domaines_connus(mail)
    seuil_spam = mail.loc[mail["verdict"] == "spam", "score_risque"].min()
    m = mail[mail["verdict"] == "livre"].copy()
    m["dom_expediteur"] = m["expediteur"].map(domaine)
    m["imite"] = m["dom_expediteur"].map(lambda d: sosie(d, connus))
    pj = m["piece_jointe"].fillna("").str.lower()
    m["double_extension"] = pj.str.contains(r"\.(?:pdf|doc|docx|xls|xlsx|zip)\.(?:htm|html|exe|js|scr)$", regex=True)
    m["lien_externe"] = m["lien"].notna()
    m["proche_seuil"] = m["score_risque"] >= seuil_spam - 15
    m["signaux"] = m[["double_extension", "lien_externe", "proche_seuil"]].sum(axis=1) + m["imite"].notna()
    m["seuil_spam"] = seuil_spam
    return m[m["signaux"] > 0].sort_values(["signaux", "score_risque"], ascending=False)


def clics_hameconnage(proxy: pd.DataFrame, suspects: pd.DataFrame) -> pd.DataFrame:
    """Visites web vers un hôte cité dans un courriel suspect, ou classées « hameçonnage » par le proxy."""
    hotes = {urlparse(l).hostname for l in suspects["lien"].dropna()}
    return proxy[proxy["host"].isin(hotes) | (proxy["categorie"] == "hameconnage")].sort_values("horodatage")


def vpn_anormal(vpn: pd.DataFrame) -> pd.DataFrame:
    """Connexions VPN hors de France, et adresses IP vues avec plusieurs pays (géolocalisation incohérente)."""
    pays_par_ip = vpn.groupby("ip_source")["pays"].nunique()
    multi = pays_par_ip[pays_par_ip > 1].index
    v = vpn[(vpn["pays"] != "FR") | vpn["ip_source"].isin(multi)].copy()
    v["fin_session"] = v["horodatage"] + pd.to_timedelta(v["duree_min"], unit="m")
    v["heure_nuit"] = ~v["horodatage"].dt.hour.between(7, 19)
    return v.sort_values("horodatage")


def compte_compromis(mail_susp: pd.DataFrame, clics: pd.DataFrame, vpn_suspect: pd.DataFrame) -> dict | None:
    """Recoupe les trois sources : courriel reçu → clic sur le lien → VPN anormal pour le même compte."""
    for _, m in mail_susp.iterrows():
        login = m["destinataire"].split("@")[0]
        c = clics[(clics["login"] == login) & (clics["horodatage"] >= m["horodatage"]) &
                  (clics["horodatage"] <= m["horodatage"] + FENETRE_CLIC)]
        v = vpn_suspect[(vpn_suspect["login"] == login) & (vpn_suspect["horodatage"] > m["horodatage"])]
        if len(c) and len(v):
            premiere = v[v["resultat"] == "succes"].iloc[0]
            return {"login": login, "mail": m, "clics": c, "vpn": v, "premiere_connexion": premiere,
                    "ip_attaquant": premiere["ip_source"]}
    return None
