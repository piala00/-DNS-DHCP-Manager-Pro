# GTC Network IP Manager Pro

Logiciel Windows (interface graphique, en français) pour **inventorier les ordinateurs du domaine Active Directory**,
**observer les équipements réellement présents sur le réseau** et **proposer des adresses IP sûres** pour de nouveaux postes.
Il fonctionne en **lecture seule** : il ne modifie ni l'AD, ni le DHCP, ni le DNS, ni vos cartes réseau.

## Utilisation (sans terminal, sans Python)
1. Lancez `GTC_Network_IP_Manager_Pro.exe` (aucune installation, Python non requis).
2. **Accueil** : vérifiez les réseaux cochés (seules les plages cochées sont sondées), puis cliquez **Analyser mon réseau**.
   Vous pouvez annuler à tout moment. Le tableau de bord affiche domaine, contrôleurs, DNS, DHCP, machines AD, IP occupées, candidates, conflits.
3. **Machines du domaine** : objets ordinateur AD, résolution DNS, et *vérification* (active / DNS seul / sans enregistrement…).
4. **Équipements du réseau** : hôtes observés (ping, ARP, DNS inverse), y compris hors domaine.
5. **Plan d'adressage** : statut de chaque IP avec justification et horodatage ; **adresses candidates** ; bouton **Vérifier l'adresse** ;
   **Fiche de configuration** pour le nouveau poste.
6. **Rapports** : export CSV (UTF-8 BOM), XLSX (feuilles Machines AD, Réseau, DHCP, Plan, Conflits, Diagnostic, Sources) et diagnostic JSON.

## Statuts d'adresses
`OCCUPÉE`, `RÉSERVÉE`, `EXCLUE`, `DHCP_DYNAMIQUE`, `CONFLIT`, `INCONNUE`, `CANDIDATE_À_VÉRIFIER`, `DISPONIBLE_CONFIRMÉE`.
**Une absence de réponse au ping n'est jamais une preuve d'adresse libre.** `DISPONIBLE_CONFIRMÉE` n'est attribuée que si
ICMP/ARP, DNS (A/PTR), AD et DHCP (lu en administration) concordent sur un segment local ; elle reste conditionnelle et datée.
Les plages DHCP dynamiques ne sont jamais proposées comme IP statiques ; les exclusions DHCP sont privilégiées.

## Droits et limites
- Domaine : détection Windows + requête SRV + LDAP (ADSI) avec la session en cours. Aucun mot de passe n'est demandé ni stocké.
- DHCP : nécessite le module PowerShell `DhcpServer` (RSAT) et des droits de lecture ; sinon la source est marquée « inaccessible » et aucune IP n'est confirmée.
- Sous-réseau distant : l'ARP n'est pas visible, le silence ICMP n'est pas concluant → au mieux `CANDIDATE_À_VÉRIFIER`.
- `172.168.x.x` n'est **pas** une plage privée RFC1918 (privées : 10/8, 172.16/12, 192.168/16) : un avertissement s'affiche.
- La résolution DNS utilise le résolveur Windows (peut inclure LLMNR/NetBIOS). IPv6 non pris en charge dans cette version.
- Journaux : `%APPDATA%\GTC_Network_IP_Manager_Pro\logs`. Paramètres : `%APPDATA%\GTC_Network_IP_Manager_Pro\settings.json`.

## Développement
```
pip install -r requirements-dev.txt
python -m pyflakes gtc_ipm tests main.py
python -m pytest tests            # données simulées (signalées comme telles)
python tests/windows_smoke.py     # test réel, Windows uniquement
python main.py                    # lancer l'application
```
Architecture : `gtc_ipm/{ui,discovery,ad,dhcp,dns,planning,reports,core}`. Compilation : voir le workflow
`.github/workflows/gtc-network-ip-manager-pro.yml` (PyInstaller `--onefile --windowed`, x64).
