# Opération Brume – investigation SOC en Python

Projet PYS-701 « Python pour la sécurité » (M1, École PMN) – Priscilla MANEDJI NGOUANA (projet réalisé en solo, avec accord de l'intervenant).

À partir de 7 journaux (VPN, Active Directory, proxy web, pare-feu, messagerie, EDR, inventaire), ces scripts
reconstituent l'attaque subie par l'entreprise fictive Nordis Logistique. **Aucune réponse n'est codée en dur** :
chaque compte, adresse ou hôte est déduit des données, et chaque résultat est affiché avec sa preuve
(`fichier, ligne, champ`).

## 1. Installation

```bash
# avec conda (recommandé)
conda create -n brume python=3.12 -y && conda activate brume
pip install -r requirements.txt

# ou avec venv
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
```

## 2. Données (non versionnées)

Télécharger `operation-brume-donnees.zip` depuis la page du projet du cours PYS-701, puis :

```bash
unzip operation-brume-donnees.zip -d tmp && mv tmp/donnees ./donnees && rm -r tmp
```

Le dossier `donnees/` doit contenir les 7 fichiers (`vpn_auth.csv`, `ad_events.jsonl`, `proxy_web.csv`,
`firewall.csv`, `mail_gateway.csv`, `edr_alerts.json`, `inventaire_parc.csv`).

## 3. Exécution

Chaque script correspond à un niveau de l'énoncé. Ils sont indépendants et peuvent être relancés à tout moment.

| Commande | Niveau | Question traitée |
|---|---|---|
| `python3 01_normale.py` | 1 | Effectifs, période, journée normale |
| `python3 02_entree.py` | 2 | Courriel piégé → hameçonnage → connexion VPN de l'attaquant |
| `python3 03_progression.py` | 3 | Balayage interne, compte à privilèges, compte de persistance |
| `python3 04_impact.py` | 4 | Volume exfiltré, alertes EDR restées sans réaction |
| `python3 05_chronologie.py` | 5 | Chronologie, indicateurs de compromission, règles de détection testées |

Options : `--donnees CHEMIN` (défaut `donnees`) et `--sortie CHEMIN` (défaut `resultats`).
Les tableaux (`.csv`) et graphiques (`.png`) sont écrits dans `resultats/`.

## 4. Tests

```bash
python3 -m pytest -q
```

Les tests unitaires vérifient la logique des règles (sosie de domaine, balayage, rafale d'échecs) sur des données
fabriquées ; les tests d'intégration vérifient la traçabilité et la cohérence entre sources sur les vraies données.

## 5. Organisation du code

```
brume/chargement.py   chargement des 7 sources + colonnes de traçabilité (fichier, ligne)
brume/normale.py      niveau 1 : référence du « normal »
brume/entree.py       niveau 2 : courriels, hameçonnage, VPN
brume/progression.py  niveau 3 : balayage, force brute, persistance
brume/impact.py       niveau 4 : exfiltration, EDR
brume/enquete.py      enchaînement des niveaux, chronologie et IoC
brume/regles.py       règles de détection proposées et leur évaluation
```

## 6. Usage de l'IA

Un assistant d'IA générative (Claude, Anthropic) a aidé à structurer et écrire le code. Chaque script a été relancé,
lu et compris ; les résultats et les conclusions du rapport sont vérifiés sur les données.

## 7. Sécurité

Projet 100 % défensif : lecture de journaux fictifs uniquement. Aucune donnée réelle, aucun code offensif.
Les scripts ne font que lire les fichiers et n'exécutent aucun contenu issu des journaux.

## Résultats attendus

| Script | Fichiers produits dans `resultats/` |
|---|---|
| 01_normale.py | periode.csv, profil_*.csv, journee_type.png |
| 02_entree.py | mails_suspects.csv, vpn_anormal.csv |
| 03_progression.py | balayage.csv, rafales_echecs.csv, comptes_crees.csv |
| 04_impact.py | envois_par_hote.csv, exfiltration.csv, exfiltration.png |
| 05_chronologie.py | chronologie.csv, iocs.csv, regles_detection.csv, frise.png |

Le rapport d'investigation est dans `docs/`.
