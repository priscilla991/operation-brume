#!/usr/bin/env python3
"""
Niveau 5 – Conclure : chronologie complète, indicateurs de compromission (IoC) et règles de détection testées.
Toutes les valeurs sont déduites des données par les modules du paquet ``brume`` (aucune réponse codée en dur).

    python3 05_chronologie.py --donnees ./donnees
Produit : resultats/chronologie.csv, iocs.csv, regles_detection.csv, frise.png
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

from brume import arguments
from brume.chargement import charger, titre
from brume import enquete, regles

args = arguments(__doc__)
data = charger(args.donnees)
r = enquete.reconstituer(data)

titre("1. Chronologie de l'attaque (une ligne = un fait prouvé)")
chrono = enquete.chronologie(data, r)
with pd.option_context("display.max_colwidth", 95, "display.width", 200):
    print(chrono.to_string(index=False))
chrono.to_csv(args.sortie / "chronologie.csv", index=False)
duree = chrono["horodatage"].max() - chrono["horodatage"].min()
j, sec = duree.days, duree.seconds
print(f"\n  Durée totale : {j} j {sec // 3600} h {sec % 3600 // 60:02d} (du courriel piégé à la dernière alerte)")

titre("2. Indicateurs de compromission")
ioc = enquete.indicateurs(r)
print(ioc.to_string(index=False))
ioc.to_csv(args.sortie / "iocs.csv", index=False)

titre(f"3. Règles de détection testées sur 3 semaines (sabotage le {r['debut_sabotage']})")
ev = regles.evaluer(data, r["debut_sabotage"])
with pd.option_context("display.max_colwidth", 70, "display.width", 200):
    print(ev.to_string(index=False))
ev.to_csv(args.sortie / "regles_detection.csv", index=False)
print("\n  Lecture : une règle utile alerte TÔT (grande avance) et RAREMENT (peu de bruit).")

# ---------------------------------------------------------------- frise
couleurs = {"1. Entrée": "#2a78d6", "2. Progression": "#eda100", "3. Persistance": "#6250d6",
            "4. Accès aux serveurs": "#8a9a95", "5. Exfiltration": "#c0392b", "6. Alertes EDR": "#1b2623"}
cles = list(couleurs)
fig, ax = plt.subplots(figsize=(11, 3.6), dpi=150)
for etape, grp in chrono.groupby("etape"):
    y = cles.index(etape)
    ax.scatter(grp["horodatage"], [y] * len(grp), s=40, color=couleurs.get(etape, "grey"), zorder=3)
ax.set_yticks(range(len(cles)), cles, fontsize=8)
ax.invert_yaxis()
ax.grid(axis="x", color="#e3e8e6")
ax.set_title("Opération Brume – frise de l'attaque (chaque point = un fait prouvé dans les journaux)", fontsize=10)
ax.spines[["top", "right"]].set_visible(False)
plt.tight_layout(); plt.savefig(args.sortie / "frise.png")
print(f"\n  Frise : {args.sortie / 'frise.png'}")
