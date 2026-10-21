"""Niveau 1 – Comprendre les données et caractériser une journée « normale »."""
import pandas as pd

HEURES_OUVREES = range(7, 20)   # 7 h – 19 h 59


def effectifs(data: dict) -> dict:
    inv = data["inventaire"]
    return {
        "postes": int((inv["type"] == "poste").sum()),
        "serveurs": int((inv["type"] == "serveur").sum()),
        "utilisateurs_inventaire": int(inv["proprietaire"].nunique()),
        "utilisateurs_ad": int(data["ad"]["utilisateur"].nunique()),
        "sites": inv["site"].value_counts().to_dict(),
        "liste_serveurs": inv.loc[inv["type"] == "serveur", ["hostname", "ip", "site", "os"]],
    }


def periode(data: dict) -> pd.DataFrame:
    lignes = []
    for nom, df in data.items():
        if "horodatage" in df:
            lignes.append({"source": nom, "fichier": df["fichier"].iloc[0], "lignes": len(df),
                           "debut": df["horodatage"].min(), "fin": df["horodatage"].max()})
    return pd.DataFrame(lignes)


def profil_journalier(data: dict) -> pd.DataFrame:
    """Volume d'événements par jour et par source (base de comparaison)."""
    series = {}
    for nom in ["proxy", "firewall", "ad", "vpn", "mail"]:
        df = data[nom]
        series[nom] = df.groupby(df["horodatage"].dt.date).size()
    jours = pd.DataFrame(series).fillna(0).astype(int)
    jours.index = pd.to_datetime(jours.index)
    jours["jour_semaine"] = jours.index.day_name(locale=None)
    jours["week_end"] = jours.index.dayofweek >= 5
    return jours


def profil_horaire(data: dict) -> pd.DataFrame:
    """Répartition horaire moyenne (jours ouvrés) : proxy, connexions AD réussies, VPN."""
    res = {}
    for nom, filtre in [("proxy", None), ("ad", 4624), ("vpn", None)]:
        df = data[nom]
        if filtre is not None:
            df = df[df["event_id"] == filtre]
        df = df[df["horodatage"].dt.dayofweek < 5]
        n_jours = df["horodatage"].dt.date.nunique()
        res[nom] = df.groupby(df["horodatage"].dt.hour).size() / max(n_jours, 1)
    return pd.DataFrame(res).reindex(range(24)).fillna(0).round(1)


def reperes_normaux(data: dict) -> dict:
    """Quelques repères chiffrés qui serviront de seuils pour repérer l'anormal."""
    vpn, ad, proxy, mail, edr = data["vpn"], data["ad"], data["proxy"], data["mail"], data["edr"]
    hors_heures = ~proxy["horodatage"].dt.hour.isin(HEURES_OUVREES)
    envoi_jour_hote = proxy.groupby([proxy["horodatage"].dt.date, "host"])["octets_envoyes"].sum()
    return {
        "vpn_part_france": round((vpn["pays"] == "FR").mean() * 100, 2),
        "vpn_echecs_par_jour": round((vpn["resultat"] == "echec").sum() / vpn["horodatage"].dt.date.nunique(), 1),
        "ad_echecs_par_jour": round((ad["event_id"] == 4625).sum() / ad["horodatage"].dt.date.nunique(), 1),
        "proxy_part_hors_heures": round(hors_heures.mean() * 100, 2),
        "proxy_envoi_median_par_hote_jour_ko": round(envoi_jour_hote.median() / 1e3, 1),
        "proxy_envoi_p99_par_hote_jour_mo": round(envoi_jour_hote.quantile(0.99) / 1e6, 2),
        "mail_score_max_livre": int(mail.loc[mail["verdict"] == "livre", "score_risque"].max()),
        "mail_score_min_spam": int(mail.loc[mail["verdict"] == "spam", "score_risque"].min()),
        "edr_part_faux_positifs": round((edr["statut"] == "clos_faux_positif").mean() * 100, 1),
    }
