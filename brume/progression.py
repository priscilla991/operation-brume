"""Niveau 3 – Suivre la progression : balayage interne, compte à privilèges, persistance."""
from __future__ import annotations

import pandas as pd

SEUIL_BALAYAGE = 10                     # couples (destination, port) distincts
FENETRE_BALAYAGE = "1min"
SEUIL_RAFALE = 5                        # échecs d'authentification
FENETRE_RAFALE = pd.Timedelta(minutes=10)
DELAI_SUCCES = pd.Timedelta(minutes=15)
GROUPES_ADMIN = ("admins du domaine", "administrateurs", "admins de l'entreprise")


def ips_hors_inventaire(fw: pd.DataFrame, inventaire: pd.DataFrame) -> pd.DataFrame:
    """Adresses sources internes (10.x) du pare-feu absentes de l'inventaire."""
    connues = set(inventaire["ip"])
    internes = fw[fw["ip_source"].str.startswith("10.")]
    inconnues = internes[~internes["ip_source"].isin(connues)]
    return (inconnues.groupby("ip_source")
            .agg(evenements=("ligne", "size"), premiere=("horodatage", "min"), derniere=("horodatage", "max"),
                 destinations=("ip_dest", "nunique"), ports=("port_dest", lambda p: sorted(set(p))))
            .sort_values("evenements", ascending=False))


def detecter_balayage(fw: pd.DataFrame, seuil: int = SEUIL_BALAYAGE, fenetre: str = FENETRE_BALAYAGE) -> pd.DataFrame:
    """Fenêtres où une même source touche au moins ``seuil`` couples (destination, port) distincts."""
    f = fw.assign(cible=fw["ip_dest"] + ":" + fw["port_dest"].astype(str),
                  tranche=fw["horodatage"].dt.floor(fenetre))
    g = f.groupby(["ip_source", "tranche"]).agg(
        couples=("cible", "nunique"), destinations=("ip_dest", "nunique"),
        ports=("port_dest", lambda p: sorted(set(p))), bloques=("action", lambda a: (a == "bloque").sum()),
        premiere_ligne=("ligne", "min"))
    return g[g["couples"] >= seuil].reset_index().sort_values("tranche")


def sessions_vpn_couvrant(horodatages: pd.Series, vpn: pd.DataFrame) -> pd.DataFrame:
    """Sessions VPN réussies actives au moment des événements donnés (rattache une IP interne à une session)."""
    s = vpn[vpn["resultat"] == "succes"].copy()
    s["fin_session"] = s["horodatage"] + pd.to_timedelta(s["duree_min"], unit="m")
    lignes = []
    for t in horodatages:
        actives = s[(s["horodatage"] <= t) & (s["fin_session"] >= t)]
        for _, a in actives.iterrows():
            lignes.append({"evenement": t, "login": a["login"], "ip_vpn": a["ip_source"], "pays": a["pays"],
                           "debut_session": a["horodatage"], "ligne_vpn": a["ligne"]})
    return pd.DataFrame(lignes)


def rafales_echecs(ad: pd.DataFrame, seuil: int = SEUIL_RAFALE) -> pd.DataFrame:
    """Rafales d'échecs (4625) sur un même compte depuis une même source, suivies d'un succès (4624)."""
    echecs = ad[ad["event_id"] == 4625].sort_values("horodatage")
    succes = ad[ad["event_id"] == 4624]
    resultats = []
    for (user, src), grp in echecs.groupby(["utilisateur", "ip_source"]):
        t = grp["horodatage"].reset_index(drop=True)
        for i in range(len(t)):
            fen = t[(t >= t[i]) & (t <= t[i] + FENETRE_RAFALE)]
            if len(fen) >= seuil:
                fin = fen.max()
                ok = succes[(succes["utilisateur"] == user) & (succes["ip_source"] == src) &
                            (succes["horodatage"] > fin) & (succes["horodatage"] <= fin + DELAI_SUCCES)]
                resultats.append({"utilisateur": user, "ip_source": src, "debut": t[i], "fin": fin,
                                  "echecs": len(fen), "succes_ensuite": len(ok) > 0,
                                  "heure_succes": ok["horodatage"].min() if len(ok) else pd.NaT,
                                  "ligne_succes": ok["ligne"].min() if len(ok) else None,
                                  "lignes_echecs": f"{grp['ligne'].min()}–{grp['ligne'].max()}"})
                break
    return pd.DataFrame(resultats)


def privileges(ad: pd.DataFrame, utilisateur: str) -> pd.DataFrame:
    """Événements 4672 (privilèges spéciaux) d'un compte : preuve qu'il s'agit d'un compte d'administration."""
    return ad[(ad["event_id"] == 4672) & (ad["utilisateur"] == utilisateur)]


def creations_et_ajouts_admin(ad: pd.DataFrame) -> pd.DataFrame:
    """Créations de comptes (4720) et ajouts à un groupe d'administration (4728/4732/4756)."""
    c = ad[ad["event_id"].isin([4720, 4728, 4732, 4756])].copy()
    c["compte"] = c["compte_cree"].fillna(c["compte_ajoute"])
    c["groupe_admin"] = c["groupe"].fillna("").str.lower().isin(GROUPES_ADMIN)
    c["hors_heures"] = ~c["horodatage"].dt.hour.between(7, 19)
    c["source_externe"] = ~c["ip_source"].astype(str).str.match(r"^(10\.|PC-|SRV-)")
    return c.sort_values("horodatage")


def persistance(ad: pd.DataFrame) -> pd.DataFrame:
    """Comptes créés PUIS ajoutés à un groupe d'administration : le compte de maintien de l'attaquant."""
    c = creations_et_ajouts_admin(ad)
    ajoutes = c[(c["event_id"] != 4720) & c["groupe_admin"]]
    return c[c["compte"].isin(ajoutes["compte"])]


def activite_compte(ad: pd.DataFrame, compte: str) -> pd.DataFrame:
    """Toutes les connexions d'un compte (pour suivre ce que l'attaquant en a fait)."""
    return ad[(ad["utilisateur"] == compte) & (ad["event_id"] == 4624)].sort_values("horodatage")
