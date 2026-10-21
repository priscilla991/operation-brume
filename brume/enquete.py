"""
Enchaîne les analyses pour reconstituer l'attaque, SANS valeur codée en dur :
chaque élément (compte, adresse, hôte) est déduit des données par l'étape précédente.
Utilisé par 05_chronologie.py et par les tests.
"""
from __future__ import annotations

import pandas as pd

from . import entree, impact, progression
from .chargement import ip_vers_machine


def reconstituer(data: dict) -> dict:
    r = {}
    # Niveau 2 : point d'entrée
    susp = entree.mails_suspects(data["mail"])
    clics = entree.clics_hameconnage(data["proxy"], susp)
    vpn_s = entree.vpn_anormal(data["vpn"])
    cc = entree.compte_compromis(susp, clics, vpn_s)
    if cc is None:
        raise RuntimeError("Aucun compte compromis identifié par recoupement courriel → clic → VPN.")
    r.update(login_initial=cc["login"], mail=cc["mail"], clics=cc["clics"], vpn=cc["vpn"],
             vpn_premiere=cc["premiere_connexion"], ip_attaquant=cc["ip_attaquant"])

    # Niveau 3 : progression
    inconnues = progression.ips_hors_inventaire(data["firewall"], data["inventaire"])
    ip_interne = inconnues.index[0] if len(inconnues) else None
    r["ip_interne"] = ip_interne
    r["ip_interne_infos"] = inconnues.iloc[0] if len(inconnues) else None
    bal = progression.detecter_balayage(data["firewall"])
    r["balayage"] = bal[bal["ip_source"] == ip_interne] if ip_interne else bal
    if ip_interne:
        evts = data["firewall"].loc[data["firewall"]["ip_source"] == ip_interne, "horodatage"]
        r["rattachement_vpn"] = progression.sessions_vpn_couvrant(evts, data["vpn"])
    raf = progression.rafales_echecs(data["ad"])
    raf = raf[raf["succes_ensuite"] & (raf["ip_source"] == r["ip_attaquant"])]
    r["rafale"] = raf
    r["compte_admin"] = raf.iloc[0]["utilisateur"] if len(raf) else None
    r["privileges"] = progression.privileges(data["ad"], r["compte_admin"]) if r["compte_admin"] else None
    pers = progression.persistance(data["ad"])
    r["persistance"] = pers
    r["compte_persistance"] = pers.iloc[0]["compte"] if len(pers) else None
    r["groupe"] = pers["groupe"].dropna().iloc[0] if len(pers) else None

    # Niveau 4 : impact
    env = impact.envois_par_hote(data["proxy"])
    r["envois"] = env
    r["exfil"] = impact.exfiltration(data["proxy"], env.index[0])
    r["edr"] = impact.alertes_edr(data["edr"])
    acc = impact.acces_serveurs(data["ad"], data["firewall"], r["compte_persistance"], ip_interne)
    acc["cible"] = acc["cible"].map(lambda c: ip_vers_machine(data["inventaire"]).get(c, c))
    r["acces_serveurs"] = acc
    ouvertes = r["edr"]["ouvertes"]
    sab = ouvertes[ouvertes["titre"].str.contains("sauvegarde|rançongiciel|chiffrement", case=False, regex=True)]
    r["debut_sabotage"] = sab["horodatage"].min() if len(sab) else data["edr"]["horodatage"].max()
    return r


def chronologie(data: dict, r: dict) -> pd.DataFrame:
    """Frise unique de l'attaque : une ligne par fait, avec sa preuve (fichier, ligne)."""
    ev = []

    def add(t, etape, fait, fichier, ligne):
        ev.append({"horodatage": t, "etape": etape, "fait": fait, "fichier": fichier, "ligne": ligne})

    m = r["mail"]
    add(m["horodatage"], "1. Entrée", f"Courriel piégé livré à {m['destinataire']} (score {m['score_risque']}, "
        f"pièce jointe {m['piece_jointe']}, expéditeur {m['expediteur']})", m["fichier"], m["ligne"])
    for _, c in r["clics"].iterrows():
        add(c["horodatage"], "1. Entrée", f"{c['login']} ({c['ip_source']}) : {c['methode']} {c['host']}{c['url']}",
            c["fichier"], c["ligne"])
    for _, v in r["vpn"].iterrows():
        add(v["horodatage"], "1. Entrée", f"VPN {v['resultat']} {v['login']} depuis {v['ip_source']} ({v['pays']})"
            + (f" – {v['motif']}" if pd.notna(v["motif"]) else ""), v["fichier"], v["ligne"])
    if len(r["balayage"]):
        b = r["balayage"].iloc[0]
        add(b["tranche"], "2. Progression", f"Balayage interne depuis {b['ip_source']} : {b['destinations']} serveurs, "
            f"ports {b['ports']}", "firewall.csv", b["premiere_ligne"])
    for _, x in r["rafale"].iterrows():
        add(x["debut"], "2. Progression", f"Rafale de {x['echecs']} échecs sur {x['utilisateur']} depuis {x['ip_source']}",
            "ad_events.jsonl", x["lignes_echecs"])
        add(x["heure_succes"], "2. Progression", f"Connexion réussie de {x['utilisateur']} (compte à privilèges)",
            "ad_events.jsonl", int(x["ligne_succes"]))
    for _, p in r["persistance"].iterrows():
        txt = (f"Création du compte {p['compte']}" if p["event_id"] == 4720
               else f"Ajout de {p['compte']} au groupe « {p['groupe']} »")
        add(p["horodatage"], "3. Persistance", f"{txt} par {p['utilisateur']} depuis {p['ip_source']}", p["fichier"], p["ligne"])
    acc = r["acces_serveurs"].copy()
    acc["nuit"] = (acc["horodatage"] - pd.Timedelta(hours=12)).dt.date   # regroupe une nuit (avant/après minuit)
    for _, g in acc.groupby("nuit"):
        cibles = ", ".join(sorted(set(g["cible"])))
        fichiers = ", ".join(sorted(set(g["fichier"])))
        n_rdp = int((g["source"].str.startswith("Pare-feu")).sum())
        n_ad = len(g) - n_rdp
        txt = f"{n_rdp} sessions RDP depuis {r['ip_interne']}"
        if n_ad:
            txt += f" et {n_ad} connexion(s) du compte {r['compte_persistance']}"
        add(g["horodatage"].min(), "4. Accès aux serveurs",
            f"{txt} vers {cibles}, jusqu'à {g['horodatage'].max():%H:%M}", fichiers, f"{g['ligne'].min()}–{g['ligne'].max()}")
    e = r["exfil"]
    add(e["debut"], "5. Exfiltration", f"Début des envois vers {e['hote']} ({e['requetes']} requêtes, {e['go']} Go au total)",
        "proxy_web.csv", e["lignes"])
    for _, a in r["edr"]["ouvertes"].iterrows():
        add(a["horodatage"], "6. Alertes EDR", f"[{a['gravite']}] {a['titre']} sur {a['machine']} – resté « {a['statut']} »",
            a["fichier"], a["ligne"])
    return pd.DataFrame(ev).sort_values("horodatage").reset_index(drop=True)


def indicateurs(r: dict) -> pd.DataFrame:
    """Tableau récapitulatif des indicateurs de compromission (IoC)."""
    e, m = r["exfil"], r["mail"]
    lien = m["lien"] if pd.notna(m["lien"]) else ""
    ioc = [
        ("Adresse IP externe", r["ip_attaquant"], "Connexions VPN et AD de l'attaquant", "vpn_auth.csv, ad_events.jsonl"),
        ("Adresse IP interne", r["ip_interne"], "Adresse VPN attribuée à l'attaquant, absente de l'inventaire", "firewall.csv"),
        ("Domaine", m["expediteur"].split("@")[1], "Expéditeur sosie du courriel piégé", "mail_gateway.csv"),
        ("Domaine", lien.split("/")[2] if lien else "", "Page d'hameçonnage", "mail_gateway.csv, proxy_web.csv"),
        ("Domaine", e["hote"], "Destination de l'exfiltration", "proxy_web.csv"),
        ("Fichier", m["piece_jointe"], "Pièce jointe à double extension", "mail_gateway.csv"),
        ("Compte", r["login_initial"], "Compte compromis par hameçonnage", "mail, proxy, vpn"),
        ("Compte", r["compte_admin"], "Compte à privilèges compromis par force brute", "ad_events.jsonl"),
        ("Compte", r["compte_persistance"], f"Compte créé par l'attaquant, ajouté à « {r['groupe']} »", "ad_events.jsonl, edr"),
    ]
    for p in e["postes"]:
        ioc.append(("Machine", p, "Poste d'où sont parties les données", "proxy_web.csv, edr_alerts.json"))
    for s in sorted(set(r["acces_serveurs"]["cible"])):
        ioc.append(("Machine", s, "Serveur accédé par l'attaquant", "ad_events.jsonl, firewall.csv"))
    return pd.DataFrame(ioc, columns=["type", "valeur", "role", "sources"])
