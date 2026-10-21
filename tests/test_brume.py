"""
Tests automatiques (module 5 : automatiser, tester, sécuriser).
  - Tests unitaires sur de petites données fabriquées : ils vérifient la LOGIQUE des règles.
  - Tests d'intégration sur les vraies données (ignorés si le dossier donnees/ est absent).
Lancer : python3 -m pytest -q
"""
from datetime import timedelta, timezone
from pathlib import Path

import pandas as pd
import pytest

from brume import entree, progression
from brume.chargement import charger

T0 = pd.Timestamp("2026-09-14 02:00", tz=timezone(timedelta(hours=2)))


def test_domaine_sosie_detecte():
    assert entree.sosie("fourniseur-x.example", ["fournisseur-x.example"]) == "fournisseur-x.example"
    assert entree.sosie("fournisseur-x.example", ["fournisseur-x.example"]) is None   # identique = légitime
    assert entree.sosie("banque.example", ["fournisseur-x.example"]) is None          # trop différent


def test_balayage_detecte_et_trafic_normal_ignore():
    lignes = [{"horodatage": T0 + pd.Timedelta(seconds=i), "ip_source": "10.9.9.9", "ip_dest": f"10.0.0.{i % 4}",
               "port_dest": [22, 445, 3389][i % 3], "action": "bloque", "ligne": i} for i in range(12)]
    lignes += [{"horodatage": T0, "ip_source": "10.1.1.1", "ip_dest": "10.0.0.5", "port_dest": 53,
                "action": "autorise", "ligne": 99}]
    b = progression.detecter_balayage(pd.DataFrame(lignes))
    assert list(b["ip_source"]) == ["10.9.9.9"]


def test_rafale_puis_succes():
    ev = [{"horodatage": T0 + pd.Timedelta(seconds=20 * i), "event_id": 4625, "utilisateur": "x", "ip_source": "1.2.3.4",
           "ligne": i} for i in range(6)]
    ev.append({"horodatage": T0 + pd.Timedelta(minutes=4), "event_id": 4624, "utilisateur": "x", "ip_source": "1.2.3.4",
               "ligne": 10})
    r = progression.rafales_echecs(pd.DataFrame(ev))
    assert len(r) == 1 and bool(r.iloc[0]["succes_ensuite"])


def test_quelques_echecs_isoles_ignores():
    ev = [{"horodatage": T0 + pd.Timedelta(hours=i), "event_id": 4625, "utilisateur": "y", "ip_source": "PC-1",
           "ligne": i} for i in range(6)]
    assert progression.rafales_echecs(pd.DataFrame(ev)).empty


DONNEES = Path(__file__).resolve().parents[1] / "donnees"


@pytest.mark.skipif(not DONNEES.exists(), reason="données absentes")
def test_chargement_et_tracabilite():
    data = charger(DONNEES)
    assert set(data) == {"vpn", "proxy", "firewall", "mail", "inventaire", "ad", "edr"}
    for nom, df in data.items():
        assert {"fichier", "ligne"} <= set(df.columns), nom
        assert df["ligne"].is_unique, nom


@pytest.mark.skipif(not DONNEES.exists(), reason="données absentes")
def test_enquete_coherente():
    from brume import enquete
    r = enquete.reconstituer(charger(DONNEES))
    # Cohérence entre sources : l'IP qui a ouvert le VPN est celle qui force le compte admin et crée la persistance
    assert r["rafale"].iloc[0]["ip_source"] == r["ip_attaquant"]
    assert (r["persistance"]["ip_source"] == r["ip_attaquant"]).all()
    assert r["exfil"]["go"] > 0.1
