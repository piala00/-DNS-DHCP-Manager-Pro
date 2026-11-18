# GTC Printer Manager Pro 1.0.0

Détecte les imprimantes installées sur un poste Windows, sauvegarde leurs pilotes et leurs paramètres,
et les restaure sur un autre poste. **Version portable : un seul .exe, aucun Python, aucune installation.**

## Utilisation
1. Lancer `GTC_Printer_Manager_Pro.exe` (clic droit > « Exécuter en tant qu'administrateur » recommandé ;
   sinon Windows demandera l'élévation au moment d'agir).
2. Onglet **Imprimantes** : « Analyser ce poste ». Chaque imprimante est classée : standard, virtuelle (PDF), réseau,
   ou « port propre à un programme » (cas typique de l'imprimante PDF de Sage).
3. Onglet **Sauvegarde** : cocher les imprimantes, choisir le dossier (clé USB), « Sauvegarder ».
   Résultat : dossier + ZIP (inventaire.json/csv, paquets de pilotes, export PrintBrm, LISEZ-MOI).
4. Sur l'autre poste, onglet **Restauration** : charger le ZIP, lire le plan (statuts), cocher, « Restaurer ».

## Cas de l'imprimante PDF de Sage (validation des factures)
Cette imprimante utilise en général un **port propre au programme Sage**, qui n'est PAS recopiable par un
simple export de pilote. Le logiciel le détecte et vous prévient avant d'agir (statut « PORT MANQUANT »).
La méthode fiable : **réinstaller le composant Sage sur le poste cible**, puis restaurer/vérifier l'imprimante.

## Limites (à lire)
- PrintBrm ne migre que les ports TCP/IP, WSD et LPR ; même architecture/version Windows requise.
- La restauration d'une imprimante à port propre à un programme n'est pas garantie : à essayer d'abord sur un poste de test.
- Le code Windows natif est validé par la CI sur un poste Windows réel, pas sur votre matériel.
