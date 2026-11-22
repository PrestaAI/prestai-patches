# Catalogues publiés

## catalog-0001

Premier catalogue, lu par PrestAI Core 2.27.0. Les 23 failles de PrestaShop 9.0.0 à 9.2.0 corrigées par 9.1.5
(5, en août) et 9.2.1 (18, en novembre), les deux modules natifs corrigés avec 9.2.1, et la faille plus ancienne du
module correctif `pshotfix_ghsaw9f3qc75qgx9` (corrigée en 9.1.1). Branche 9.1 : plus corrigée par PrestaShop (dernière
version 9.1.5) ; branche 9.2 : corrigée (9.2.1).

Lot 1 : ce qui s'attaque sans compte ou avec un compte client, plus le rattrapage de 9.1.5. Les failles du
back-office, du Webservice et de l'API d'administration (lot 2) sont « sans correctif » pour l'instant, sauf quand une
vérification de la boutique montre qu'elle n'y est pas exposée.

Correctifs de fichiers :

| Correctif | Avis | 9.1.4 | 9.1.5 | Source dans PrestaShop |
|---|---|---|---|---|
| `concurrent-orders` | B8 (GHSA-r246-6gw4-pj3p, 7,5), B9 (GHSA-2676-hc74-gg7v, 7,5) | 5 fichiers | 5 fichiers | cfc7c45 et e0a193e (sans OrderController, B10), de 9.2.1 ; vide le cache Symfony |
| `customization-file` | B17 (GHSA-fg9q-mm4c-h5xc, 5,9) | 2 | 2 | 1a6d596 |
| `password-reset-token` | B18 (GHSA-g6p7-cx52-hcrj, 4,8) | 4 | 4 | 63cfad7 |
| `catch-up-9-1-5` | A1 à A5 (8,2 · 7,3 · 6,5 · 4,3 · 8,0) | 9 | intégré | fichiers officiels de 9.1.5 |

Vérifications de la boutique : `install_dir_absent` (B5, B6 : supprimer le dossier `install/` depuis la page),
`multishop_or_webservice` (B4, B7), `webservice_attachments` (B3), `admin_api_clients` (B1, B16). Modules natifs :
psgdpr 1.4.4 (GHSA-wwqh-cf9m-347f) et ps_emailsubscription 3.0.1 (GHSA-pg6j-qf29-gc43), « à mettre à jour » quand la
boutique a une version plus ancienne.

31 fichiers en tout (22 différents), chacun vérifié contre l'empreinte du fichier officiel avant d'être remplacé ; les
deux classes nouvelles de `concurrent-orders` sont créées par le correctif et supprimées par son retour arrière.
