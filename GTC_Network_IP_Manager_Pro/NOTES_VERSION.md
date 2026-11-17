# Notes de version 1.0.0
- Première version Pro : inventaire AD (ADSI), découverte ping/ARP/DNS inverse, lecture DHCP (module DhcpServer), plan d'adressage à statuts justifiés.
- Exports CSV (UTF-8 BOM) / XLSX / diagnostic JSON ; fiche de configuration d'un nouveau poste.
- Non validé à ce jour dans un environnement AD/DHCP de production : à essayer d'abord en lecture sur un poste de test.

## 1.1.0
- Nouveau : application d'une adresse IPv4 fixe (UAC, sauvegarde, vérification, retour arrière automatique).
- Nouveau : profils de sites nommés (enregistrer, charger, importer/exporter) ; adresses importées jamais « confirmées ».
- NON testé sur une vraie carte réseau (la CI ne modifie pas le runner) : premier essai sur un poste de test avec accès console.
