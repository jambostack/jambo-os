# ADR 0091: Pile Réseau RFC 768 UDP & Interface de Sockets POSIX en Espace Utilisateur

## Statut
Accepté (Palier 7 - Jalon v0.3.92)

## Contexte
La pile réseau de JamboOS doit fonctionner intégralement en Ring 3 au sein du démon `jambo-netd`, sans privilège superviseur et en conformité avec le modèle de sécurité capabilaire.
Pour permettre le portage d'applications et de bibliothèques C standard, le système avait besoin :
1. De constantes et structures de sockets POSIX standard (`AF_INET`, `SOCK_STREAM`, `SOCK_DGRAM`, `sockaddr_in`, `in_addr`).
2. De primitives C-ABI conformes (`socket`, `bind`, `connect`, `listen`, `accept`, `send`, `recv`, `shutdown`) intégrées à la couche VFS (`libjambo::vfs`).
3. D'une implémentation protocolaire UDP conforme à la RFC 768 avec calcul de somme de contrôle (*checksum*) sur pseudo-en-tête IPv4.
4. D'un gestionnaire de table de sockets avec allocation dynamique de ports éphémères (plage 49152..65535).

## Décision
1. **Module POSIX Réseau (`libs/libjambo/src/net.rs` & `include/jambo.h`)** :
   - Constantes protocolaires POSIX : familles d'adresses (`AF_INET = 2`, `AF_INET6 = 10`), types de sockets (`SOCK_STREAM = 1`, `SOCK_DGRAM = 2`), protocoles (`IPPROTO_TCP = 6`, `IPPROTO_UDP = 17`) et modes de fermeture (`SHUT_RD`, `SHUT_WR`, `SHUT_RDWR`).
   - Structures `InAddr` (4 octets) et `SockAddrIn` (16 octets alignés).
   - Conversions d'ordre d'octets réseau : `htons`, `ntohs`, `htonl`, `ntohl`.
   - Parseur et formateur IPv4 sans allocation dynamique.
2. **Intégration VFS & C-ABI (`libs/libjambo/src/vfs.rs`, `posix.rs`)** :
   - Ajout du variant `FdKind::Socket` dans `FdTable`.
   - Fonction `alloc_socket` réservant un descripteur de fichier libre.
   - Refus strict des opérations de positionnement (`lseek` renvoie `ESPIPE`).
   - Exportation des symboles C-ABI `extern "C"` avec documentation `# Safety`.
3. **Moteur UDP & Table de Sockets (`services/jambo-netd`)** :
   - Structure `UdpHeader` conforme RFC 768 (source_port, dest_port, length, checksum).
   - Calcul et validation du checksum UDP intégrant le pseudo-en-tête IPv4.
   - Forge et parsing de trames UDP/IPv4/Ethernet.
   - Table `SocketTable` (128 entrées) avec allocation de ports éphémères déterministe et détection de conflits de liaison (`EADDRINUSE`).

## Conséquences
- **Conformité POSIX Réseau** : Les logiciels en espace utilisateur peuvent créer et manipuler des sockets via l'API POSIX standard.
- **Isolation Micro-Noyau** : Les paquets corrompus ou hostiles sont filtrés en Ring 3 dans `jambo-netd` sans affecter la stabilité du noyau.
- **Extensibilité vers TCP/TLS** : La fondation `SocketTable` et l'interface VFS `FdKind::Socket` fournissent le cadre naturel pour l'ajout ultérieur d'une machine à états TCP.

