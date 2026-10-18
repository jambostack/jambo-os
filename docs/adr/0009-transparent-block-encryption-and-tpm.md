# ADR-0009: Chiffrement de Bloc Transparent et Scellement Matériel TPM (jambo-cryptod)

- **Statut** : Accepté
- **Date** : 2026-10-18
- **Auteur** : ASSOGBA Prudence Dieudonné

## Contexte
La protection des données au repos contre le vol physique, l'extraction de puces mémoire ou la falsification de disques virtuels est une exigence absolue pour un système d'exploitation sécurisé. Dans les OS conventionnels (Linux `dm-crypt`, Windows `BitLocker`), le chiffrement est enfoui dans l'espace privilégié monolithique, créant une surface d'attaque massive et rendant l'audit formel complexe. De plus, la gestion des clés souffre souvent d'une autorité ambiante globale.

## Décision
Implémenter le sous-système de chiffrement de bloc transparent et de scellement matériel (`jambo-cryptod`) en espace utilisateur Ring 3, reposant sur :
1. **Capacités de Volume Cryptographique (`CryptoVolumeCap`)** : L'accès aux blocs chiffrés (lecture, écriture, rotation de clé, descellement) requiert obligatoirement une capacité explicite sans autorité ambiante.
2. **Chiffrement de Secteur XTS / ChaCha20 Zéro-Allocation** : Chiffrement déterministe à la volée où chaque secteur (512 ou 4096 octets) possède un masque cryptographique dérivé de son adresse LBA (*Logical Block Address*), interdisant toute attaque par rejeu ou analyse fréquentielle de blocs identiques.
3. **Scellement Cryptographique sous Registres PCR TPM 2.0 (`TpmSealEngine`)** : Les clés maîtresses de volume sont scellées mathématiquement sous les empreintes de démarrage mesuré (*Measured Boot*) des PCR 0 à 7. Toute altération du chargeur Limine, du noyau JamboKernel ou de la configuration système empêche formellement le descellement de la clé.
4. **Interposition Neutre Ring 3** : Le composant s'interpose comme filtre entre le système de fichiers transactionnel `jambo-fs` et les pilotes de périphériques de bloc (`virtio-drv`, `nvme`), sans aucun impact sur le micro-noyau Ring 0.

## Conséquences
- Confidentialité et intégrité absolues des données persistées sur disque.
- Confinement strict : zéro cryptographie superflue en Ring 0.
- Protection mathématique garantie contre le démarrage d'un noyau non certifié ou altéré.
