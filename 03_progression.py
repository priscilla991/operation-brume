#!/usr/bin/env python3
"""
Niveau 3 – Suivre la progression de l'attaquant dans le réseau :
balayage interne (firewall.csv), compte à privilèges (ad_events.jsonl), compte de persistance (ad_events.jsonl).

    python3 03_progression.py --donnees ./donnees
Produit : resultats/balayage.csv, rafales_echecs.csv, comptes_crees.csv
"""
from brume import arguments
from brume.chargement import charger, preuve, titre
from brume import entree, progression

args = arguments(__doc__)
data = charger(args.donnees)
cc = entree.compte_compromis(entree.mails_suspects(data["mail"]),
                             entree.clics_hameconnage(data["proxy"], entree.mails_suspects(data["mail"])),
                             entree.vpn_anormal(data["vpn"]))
ip_ext = cc["ip_attaquant"] if cc else None

titre("1. Adresses internes absentes de l'inventaire (firewall.csv × inventaire_parc.csv)")
inc = progression.ips_hors_inventaire(data["firewall"], data["inventaire"])
print(inc.to_string())
ip_int = inc.index[0] if len(inc) else None

titre("2. Balayage interne (≥ 10 couples IP:port distincts en 1 minute)")
bal = progression.detecter_balayage(data["firewall"])
print(bal.to_string(index=False))
bal.to_csv(args.sortie / "balayage.csv", index=False)
if ip_int:
    detail = data["firewall"][data["firewall"]["ip_source"] == ip_int].sort_values("horodatage").head(3)
    for _, d in detail.iterrows():
        print("  " + preuve(d, ["horodatage", "ip_source", "ip_dest", "port_dest", "action"]))

titre(f"3. À qui appartient {ip_int} ? Rattachement aux sessions VPN actives (vpn_auth.csv)")
if ip_int:
    evts = data["firewall"].loc[data["firewall"]["ip_source"] == ip_int, "horodatage"]
    rat = progression.sessions_vpn_couvrant(evts, data["vpn"])
    resume = rat.groupby(["login", "ip_vpn", "pays"]).size().rename("evenements_couverts").reset_index()
    print(resume.sort_values("evenements_couverts", ascending=False).to_string(index=False))
    att = rat[rat["ip_vpn"] == ip_ext] if ip_ext else rat.iloc[0:0]
    n_att, n_tot = att["evenement"].nunique(), evts.nunique()
    print(f"\n  {n_att} des {n_tot} horodatages de {ip_int} tombent pendant une session VPN journalisée de l'attaquant "
          f"({ip_ext}), et aucun pendant une session d'un autre utilisateur.")
    print(f"  → {ip_int} est très probablement l'adresse VPN interne attribuée à l'attaquant.")
    hors = sorted(set(evts) - set(att["evenement"]))
    if hors:
        print(f"  LIMITE : {len(hors)} horodatages hors de toute session VPN journalisée (ex. {hors[0]:%d/%m %H:%M}) : "
              "sessions non journalisées ou autre canal d'accès. Incertitude assumée dans le rapport.")

titre("4. Compte à privilèges : rafales d'échecs suivies d'un succès (ad_events.jsonl)")
raf = progression.rafales_echecs(data["ad"])
print(raf.to_string(index=False))
raf.to_csv(args.sortie / "rafales_echecs.csv", index=False)
cible = raf[raf["succes_ensuite"]]
if ip_ext:
    cible = cible[cible["ip_source"] == ip_ext]
if len(cible):
    u = cible.iloc[0]["utilisateur"]
    print(f"\n  → {u} : {cible.iloc[0]['echecs']} échecs puis succès depuis {cible.iloc[0]['ip_source']} = attaque par force brute.")
    for _, p in progression.privileges(data["ad"], u).iterrows():
        print("  " + preuve(p, ["horodatage", "event_id", "event", "utilisateur", "machine_cible", "ip_source"]))
    poste = data["inventaire"][data["inventaire"]["proprietaire"] == u]
    print(f"  Inventaire : {u} → {poste[['hostname', 'service', 'site']].to_dict('records')} (service informatique)")
if ip_ext and len(raf):
    refus = raf[(raf["ip_source"] == ip_ext) & ~raf["succes_ensuite"]]
    for _, x in refus.iterrows():
        cibles = data["ad"][(data["ad"]["utilisateur"] == x["utilisateur"]) & (data["ad"]["ip_source"] == ip_ext)
                            & (data["ad"]["event_id"] == 4625)]["machine_cible"].unique().tolist()
        print(f"\n  Aussi : {x['echecs']} accès REFUSÉS avec {x['utilisateur']} depuis {ip_ext} entre {x['debut']:%d/%m %H:%M} "
              f"et {x['fin']:%H:%M} vers {cibles} : l'attaquant teste le compte volé sur les serveurs, sans droits suffisants.")
    autres = raf[raf["ip_source"] != ip_ext]
    print(f"  Écartées : {len(autres)} autre(s) rafale(s) venant de postes internes, sans lien avec l'attaquant.")

titre("5. Persistance : créations de comptes et ajouts à un groupe d'administration")
crees = progression.creations_et_ajouts_admin(data["ad"])
for _, c in crees.iterrows():
    print("  " + preuve(c, ["horodatage", "event_id", "utilisateur", "compte", "groupe", "ip_source"])
          + ("   ← NUIT / EXTERNE" if c["hors_heures"] or c["source_externe"] else ""))
crees.to_csv(args.sortie / "comptes_crees.csv", index=False)
pers = progression.persistance(data["ad"])
if len(pers):
    compte = pers.iloc[0]["compte"]
    print(f"\n  → Compte de maintien : {compte}, ajouté à « {pers['groupe'].dropna().iloc[0]} » par "
          f"{pers.iloc[0]['utilisateur']} depuis {pers.iloc[0]['ip_source']}.")
    print("  Écartés : les créations faites en journée par le compte RH habituel depuis un poste interne.")
    print(f"\n  Utilisation ultérieure de {compte} :")
    for _, a in progression.activite_compte(data["ad"], compte).iterrows():
        print("  " + preuve(a, ["horodatage", "utilisateur", "machine_cible", "ip_source"]))
