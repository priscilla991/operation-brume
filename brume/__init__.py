"""Boîte à outils de l'investigation « Opération Brume » (PYS-701)."""
import argparse
from pathlib import Path


def arguments(description: str):
    p = argparse.ArgumentParser(description=description)
    p.add_argument("--donnees", type=Path, default=Path("donnees"), help="dossier contenant les 7 fichiers")
    p.add_argument("--sortie", type=Path, default=Path("resultats"), help="dossier des résultats produits")
    a = p.parse_args()
    a.sortie.mkdir(parents=True, exist_ok=True)
    return a
