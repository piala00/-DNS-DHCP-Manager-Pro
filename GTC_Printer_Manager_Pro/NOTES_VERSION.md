# Notes de version

## 1.0.0
- Détection native (winspool + registre) : imprimantes, pilotes, ports, moniteurs, programmes probables.
- Sauvegarde : inventaire, paquets de pilotes (DriverStore), export PrintBrm, ZIP.
- Restauration : méthode sélective (pnputil + PowerShell) ou PrintBrm ; plan avec statuts, vérification finale.
- Élévation UAC automatique, aucune écriture sans confirmation.

## Non vérifié
- Restauration réelle d'une imprimante PDF Sage à port propre (nécessite un essai sur poste de test).
- Comportement avec tous les pilotes constructeurs (certains sont à installation propriétaire).
