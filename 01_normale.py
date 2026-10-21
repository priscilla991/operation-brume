#!/usr/bin/env python3
"""
Niveau 1 – Comprendre les données : effectifs, période, et à quoi ressemble une journée normale.

    python3 01_normale.py --donnees ./donnees
Produit : resultats/periode.csv, profil_journalier.csv, profil_horaire.csv, journee_type.png
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from brume import arguments
from brume.chargement import charger, titre
from brume import normale

args = arguments(__doc__)
data = charger(args.donnees)

titre("1. Effectifs de Nordis Logistique (inventaire_parc.csv)")
e = normale.effectifs(data)
print(f"  Postes : {e['postes']} · Serveurs : {e['serveurs']} · Utilisateurs (inventaire) : {e['utilisateurs_inventaire']}"
      f" · Comptes vus dans l'AD : {e['utilisateurs_ad']}")
print(f"  Machines par site : {e['sites']}")
print(e["liste_serveurs"].to_string(index=False))

titre("2. Période couverte par chaque source")
per = normale.periode(data)
print(per.to_string(index=False))
per.to_csv(args.sortie / "periode.csv", index=False)

titre("3. Journée type (moyenne des jours ouvrés, par heure)")
heures = normale.profil_horaire(data)
print(heures.T.to_string())
heures.to_csv(args.sortie / "profil_horaire.csv")

titre("4. Volumes par jour (le week-end est nettement plus calme)")
jours = normale.profil_journalier(data)
print(jours.to_string())
jours.to_csv(args.sortie / "profil_journalier.csv")
moy = jours.groupby("week_end")[["proxy", "firewall", "ad", "vpn", "mail"]].mean().round(0)
moy.index = ["jour ouvré", "week-end"]
print("\n  Moyenne par type de jour :\n" + moy.to_string())

titre("5. Repères de la normale (serviront de seuils)")
for k, v in normale.reperes_normaux(data).items():
    print(f"  {k:42} {v}")

# ---------------------------------------------------------------- graphique
fig, (a1, a2) = plt.subplots(1, 2, figsize=(12, 4), dpi=150)
a1.bar(jours.index, jours["proxy"], color=["#c9d4d0" if w else "#2a78d6" for w in jours["week_end"]])
a1.set_title("Requêtes web par jour (gris : week-end)", fontsize=10)
a1.tick_params(axis="x", rotation=60, labelsize=7)
for col, c in [("proxy", "#2a78d6"), ("ad", "#1baf7a"), ("vpn", "#eb6834")]:
    a2.plot(heures.index, heures[col] / heures[col].max(), label=col, color=c, lw=2)
a2.set_title("Profil horaire d'un jour ouvré (normalisé)", fontsize=10)
a2.set_xlabel("heure"); a2.set_xticks(range(0, 24, 2)); a2.legend(frameon=False, fontsize=8)
for ax in (a1, a2):
    ax.spines[["top", "right"]].set_visible(False)
plt.tight_layout(); plt.savefig(args.sortie / "journee_type.png")
print(f"\n  Graphique : {args.sortie / 'journee_type.png'}")
