#!/usr/bin/env python3
"""
Niveau 4 – Mesurer l'impact : volume exfiltré (proxy_web.csv) et alertes EDR restées sans réaction (edr_alerts.json).

    python3 04_impact.py --donnees ./donnees
Produit : resultats/envois_par_hote.csv, exfiltration.csv, exfiltration.png
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from brume import arguments
from brume.chargement import charger, preuve, titre
from brume import impact

JOURS = ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"]
args = arguments(__doc__)
data = charger(args.donnees)

titre("1. Hôtes externes qui ont reçu le plus de données (proxy_web.csv, champ octets_envoyes)")
env = impact.envois_par_hote(data["proxy"])
print(env.head(6).to_string())
env.to_csv(args.sortie / "envois_par_hote.csv")
hote = env.index[0]
print(f"\n  → {hote} a reçu {env.iloc[0]['x_mediane']:.0f} fois plus que l'hôte médian : hors norme.")

titre(f"2. Détail de l'exfiltration vers {hote}")
e = impact.exfiltration(data["proxy"], hote)
print(f"  Période : {e['debut']} → {e['fin']}  ({JOURS[e['debut'].dayofweek]})")
print(f"  Compte : {e['comptes']} · Poste : {e['postes']} · {e['requetes']} requêtes {e['methodes']} vers {e['urls']}")
print(f"  Volume envoyé : {e['octets']:,} octets = {e['go']} Go ({e['gio']} Gio)".replace(",", " "))
print(f"  Preuve : proxy_web.csv, lignes {e['lignes']}")
print("  Première et dernière requête :")
for _, x in e["detail"].iloc[[0, -1]].iterrows():
    print("  " + preuve(x, ["horodatage", "login", "ip_source", "methode", "host", "url", "octets_envoyes"]))
e["detail"].drop(columns=["fichier"]).to_csv(args.sortie / "exfiltration.csv", index=False)

titre("3. Alertes EDR importantes (edr_alerts.json)")
a = impact.alertes_edr(data["edr"])
print(a["par_gravite"].to_string())
print(f"\n  {a['faux_positifs']} alertes sur {a['total']} ont été closes comme faux positifs "
      f"({100 * a['faux_positifs'] / a['total']:.0f} %) : fatigue d'alerte.")
print("\n  Alertes restées OUVERTES :")
for _, x in a["ouvertes"].iterrows():
    print("  " + preuve(x, ["id", "horodatage", "machine", "utilisateur", "titre", "gravite", "statut"])
          + ("   ← nuit / week-end" if x["nuit_ou_week_end"] else ""))
    print(f"      note : {x['note_analyste']}")

# ---------------------------------------------------------------- graphique cumul
d = e["detail"]
fig, ax = plt.subplots(figsize=(7, 3), dpi=150)
ax.plot(d["horodatage"], d["octets_envoyes"].cumsum() / 1e9, color="#c0392b", lw=2)
ax.set_title(f"Données envoyées vers {hote} (cumul, Go)", fontsize=10)
ax.spines[["top", "right"]].set_visible(False)
plt.tight_layout(); plt.savefig(args.sortie / "exfiltration.png")
print(f"\n  Graphique : {args.sortie / 'exfiltration.png'}")
