# Laboratoire Hyper-V DNS & DHCP Manager Pro

## Objectif
Deux VM sur un commutateur **Private** sans connexion à la production :
- LAB-DC01 : Windows Server 2022, 4 Go RAM, 80 Go disque, 10.77.0.10/24
- LAB-CLIENT01 : Windows 11, 4 Go RAM, 64 Go disque, client DHCP

## Prérequis
Hôte Windows avec Hyper-V activé, droits administrateur, au moins 12 Go de RAM libre et 150 Go de stockage. ISO Windows Server et Windows 11 obtenus légalement. Les scripts ne téléchargent pas d'ISO ni n'installent Windows automatiquement.

## Démarrage
1. Sur l'hôte Hyper-V, exécuter PowerShell administrateur :
   `powershell -ExecutionPolicy Bypass -File .\lab\Create-Lab.ps1 -ServerIso C:\ISO\Server2022.iso -ClientIso C:\ISO\Windows11.iso`
2. Installer les systèmes dans les VM; nommer le serveur LAB-DC01.
3. Dans la VM serveur, exécuter les étapes séparément avec PowerShell administrateur :
   `powershell -ExecutionPolicy Bypass -File .\Configure-LabDC.ps1 -ConfigureNetwork`
   `powershell -ExecutionPolicy Bypass -File .\Configure-LabDC.ps1 -InstallRoles`
   `powershell -ExecutionPolicy Bypass -File .\Configure-LabDC.ps1 -PromoteForest`
4. Après redémarrage et connexion au domaine, lancer :
   `powershell -ExecutionPolicy Bypass -File .\Configure-LabDC.ps1 -ConfigureDhcp`
5. Vérifier avec `Get-ADDomain`, `Get-DnsServerZone`, `Get-DhcpServerv4Scope`, `Resolve-DnsName lab.example.test`. Démarrer le client et tester DHCP et la jonction au domaine.

## Limites et sécurité
Ne jamais exécuter ces scripts sur un serveur de production. Ils configurent le LAB, pas encore le logiciel graphique lui-même. Aucune installation de Windows ni aucun test réel n'ont encore été exécutés par ChatGPT. Pour automatiser l'intégration avec GitHub, installer un runner GitHub Actions auto-hébergé sur une machine dédiée, avec une politique de sécurité restrictive; ne pas exécuter de code de PR non fiable avec privilèges administrateur. Un runner Windows hébergé par GitHub ne garantit pas la virtualisation imbriquée nécessaire à Hyper-V.
