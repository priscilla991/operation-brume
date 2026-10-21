#!/usr/bin/env python3
"""
Niveau 2 – Trouver le point d'entrée en recoupant trois sources :
mail_gateway.csv (courriel piégé) → proxy_web.csv (clic sur le lien) → vpn_auth.csv (connexion de l'attaquant).

    python3 02_entree.py --donnees ./donnees
Produit : resultats/mails_suspects.csv, vpn_anormal.csv
"""
from brume import arguments
from brume.chargement import charger, preuve, titre
from brume import entree

args = arguments(__doc__)
data = charger(args.donnees)

titre("1. Courriels LIVRÉS présentant des signaux de piège (mail_gateway.csv)")
susp = entree.mails_suspects(data["mail"])
print(f"  Seuil de blocage observé : le plus petit score classé « spam » vaut {susp['seuil_spam'].iloc[0]}.")
print(f"  Domaines habituels : {entree.domaines_connus(data['mail'])}")
print(f"  {len(susp)} courriels livrés ont au moins un signal ; les 5 plus suspects :\n")
for _, m in susp.head(5).iterrows():
    print("  " + preuve(m, ["horodatage", "expediteur", "destinataire", "sujet", "piece_jointe", "score_risque", "lien"]))
    print(f"      signaux : {m['signaux']} · domaine sosie de : {m['imite']} · double extension : {m['double_extension']}")
susp.drop(columns=["seuil_spam"]).to_csv(args.sortie / "mails_suspects.csv", index=False)

titre("2. Clics vers le site d'hameçonnage (proxy_web.csv)")
clics = entree.clics_hameconnage(data["proxy"], susp)
for _, c in clics.iterrows():
    print("  " + preuve(c, ["horodatage", "login", "ip_source", "methode", "host", "url", "statut", "categorie"]))
print("  → Un POST vers /connexion/valider = le formulaire a été rempli : identifiants saisis sur le faux site.")

titre("3. Connexions VPN anormales (vpn_auth.csv)")
v = entree.vpn_anormal(data["vpn"])
for _, x in v.iterrows():
    print("  " + preuve(x, ["horodatage", "login", "ip_source", "pays", "resultat", "motif", "duree_min"]))
print("  → Une même adresse IP géolocalisée dans 3-4 pays différents : géolocalisation incohérente (relais / VPN).")
v.to_csv(args.sortie / "vpn_anormal.csv", index=False)

titre("4. Conclusion : recoupement courriel → clic → VPN")
cc = entree.compte_compromis(susp, clics, v)
if cc:
    p = cc["premiere_connexion"]
    print(f"  Compte compromis en premier : {cc['login']}")
    print(f"  Courriel reçu le {cc['mail']['horodatage']} · clic {len(cc['clics'])} requête(s) · "
          f"première connexion VPN réussie de l'attaquant le {p['horodatage']}")
    print(f"  Adresse de l'attaquant : {cc['ip_attaquant']} · pays déclaré : {p['pays']} · preuve : "
          f"[vpn_auth.csv, ligne {p['ligne']}]")
else:
    print("  Aucun recoupement trouvé.")
