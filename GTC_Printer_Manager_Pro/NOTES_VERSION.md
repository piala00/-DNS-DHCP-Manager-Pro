# Notes de version

## 1.0.0
- Détection native (winspool + registre) : imprimantes, pilotes, ports, moniteurs, programmes probables.
- Sauvegarde : inventaire, paquets de pilotes (DriverStore), export PrintBrm, ZIP.
- Restauration : méthode sélective (pnputil + PowerShell) ou PrintBrm ; plan avec statuts, vérification finale.
- Élévation UAC automatique, aucune écriture sans confirmation.

## Non vérifié
- Restauration réelle d'une imprimante PDF Sage à port propre (nécessite un essai sur poste de test).
- Comportement avec tous les pilotes constructeurs (certains sont à installation propriétaire).

## 1.0.1 - auto-diagnostic de démarrage
- Si Qt ne se charge pas (erreur « n'est pas une application Win32 valide »), le logiciel n'affiche plus une trace Python :
  il contrôle chaque .dll/.pyd (format, architecture x64, taille, SHA-256 via integrity.json), écrit
  `%TEMP%\GTC_Printer_Manager_Pro_diagnostic.txt` et affiche un message clair (code retour 3).
- Option `--diagnose <fichier>` : même contrôle sans lancer l'interface.
- Cause réelle de l'erreur sur les PC de GTC : NON établie à ce jour ; ce rapport sert à la trouver.
