# prestai-patches

Le catalogue des correctifs de sécurité de PrestaShop que lit **PrestAI Core** (2.27.0 et suivantes) : pour chaque
faille publiée par PrestaShop, son état sur la boutique, et, quand c'est possible sans monter de version, le correctif
à appliquer à la version exacte de la boutique (9.1.4, 9.1.5…). Core n'applique jamais rien seul : chaque correctif est
le choix d'un super administrateur, sur la page « Correctifs de sécurité » de Core ou en console.

Le contenu ne vient que de corrections déjà publiées par PrestaShop : les fichiers de `patches/` sont des fichiers de
PrestaShop (licence OSL-3.0, leur en-tête la porte), fusionnés à partir des commits de sécurité de PrestaShop. Aucun
code n'est exécuté depuis le catalogue : il ne contient que des empreintes, des chemins et des faits.

## Ce que lit Core

| Adresse | Contenu |
|---|---|
| `releases/latest/download/catalog.json` | le catalogue, format 1 |
| `releases/latest/download/catalog.json.sig` | sa signature (ECDSA P-256 sur SHA-256, DER) |
| `releases/download/catalog-NNNN/<sha256>` | un fichier corrigé, nommé par son empreinte, téléchargé seulement à l'application |

Core lit le catalogue une fois par jour (tâche `security_catalog` de son planificateur), sur « Vérifier maintenant »
ou par `php bin/console prestai:security:patches check`. Il l'accepte seulement si la signature est vérifiée par
l'une des deux clés écrites dans son code, si son format est connu et si son numéro n'est pas plus petit que le
dernier accepté (un numéro déjà accepté avec un autre contenu est refusé). Chaque fichier corrigé est vérifié contre
son empreinte avant d'être écrit, et chaque fichier de la boutique contre son empreinte « avant » : un fichier modifié
sur la boutique n'est jamais remplacé.

## Les clés

Deux clés ECDSA P-256, créées par `generer-cle-prestai-patches.ps1` ; leurs parties publiques sont dans `keys/` et
dans le code de Core (`PrestaiCoreSecurityKeys`). Changer de clé demande une nouvelle version de Core.

| Clé | Identifiant | Empreinte SHA-256 de la partie publique (DER) | Où est la partie privée |
|---|---|---|---|
| principale | `44b650dd2f39856b` | `44b650dd2f39856bfe112cd485a121d4c5e18a04be12af00879c861e529f2fcf` | sur le PC de publication, chiffrée par sa phrase de passe, et une copie hors ligne |
| secours | `f2b53b2ff6ade665` | `f2b53b2ff6ade665c95f1179aa36f33f7ab7d2cf81a98799195cf58ae5659f5b` | sur une clé USB hors ligne, jamais sur le PC |

La principale signe chaque catalogue. La secours ne sert que si la principale est perdue ou compromise : Core accepte
l'une ou l'autre, et sa page dit laquelle a signé. `bin/verify` contrôle les deux clés de `keys/` contre ces empreintes
avant de vérifier une signature.

## Le dépôt

| Chemin | Rôle |
|---|---|
| `catalog/advisories.json` | les branches de PrestaShop (encore corrigées ou non, leur dernière version) et les avis : GHSA, note CVSS, exposition, versions touchées (`from`) et corrigées (`fixed_in`), façon (`patch`, `check`, `module`, `none`), lot |
| `catalog/patches.json` | chaque correctif : ses avis, sa source dans PrestaShop (commits, façon de fusionner), le vidage du cache Symfony, et par version de PrestaShop la liste de ses fichiers |
| `patches/<correctif>/<version>/<chemin>` | les fichiers après le correctif, complets |
| `catalog/catalog.json` | le catalogue construit par `bin/build`, jamais écrit à la main |
| `catalog/catalog.json.sig` | sa signature, ajoutée par le script de publication |
| `bin/build` | construit le catalogue (Python 3, bibliothèque standard) |
| `bin/verify` | vérifie une signature avec les clés de Core (openssl) |
| `tests/ci/patches.cjs` | sur une boutique propre de chaque version, avec Core : correctifs appliqués puis retirés, failles constatées avant et refusées après |
| `tests/upgrade/upgrade.cjs` | les correctifs à travers une montée de version par l'assistant de PrestaShop |

`bin/build --number N --date AAAA-MM-JJTHH:MM:SSZ` écrit `catalog/catalog.json` et `dist/files/<sha256>`. L'empreinte
« avant » de chaque fichier est celle du fichier officiel de la version (GitHub, au tag de la version, gardé dans
`.cache/` ; ou `--prestashop <clone de PrestaShop>`), « absent » pour un fichier que le correctif crée. `bin/build
--check` reconstruit le catalogue depuis ses sources et compare les octets ; `--dist` écrit seulement les fichiers. Le
constructeur refuse ce que Core refuserait : un chemin hors de `classes/`, `controllers/`, `src/`, `{admin}/` et
`img/.htaccess`, sous `modules/`, `themes/`, `override/`, `config/`, `app/`, `vendor/`, `install/`, `var/`, `upload/`
ou `download/`, avec `..` ou absolu ; un fichier identique à l'officiel ; un avis ou un correctif qui nomme ce qui
n'existe pas.

## La CI

- À chaque push : le catalogue reconstruit à l'octet près, les fichiers PHP corrigés lisibles (`php -l`), la signature
  quand elle est là.
- À la demande (Actions > CI > Run workflow) et à chaque tag `catalog-NNNN` : en plus, sur une boutique PrestaShop
  propre de chaque version du catalogue (scripts de [prestai-ci](https://github.com/PrestaAI/prestai-ci), `v1`), avec
  la dernière release de PrestAI Core : chaque correctif « à appliquer », appliqué par la console, puis retiré ; avant
  lui, la faille constatée ; après lui, refusée, et l'usage normal (commande payée par virement, commande gratuite avec
  un bon, listes, notifications, export) ; puis la montée de version par l'assistant de PrestaShop (`bin/upgrade` de
  prestai-ci) de la plus ancienne version du catalogue à chaque version plus récente connue de l'assistant.
- La release (`release.yml`) ne publie que si tout passe, Core vérifiant lui-même la signature du catalogue.

Secrets du dépôt : `PRESTAI_CI_APP_CLIENT_ID` et `PRESTAI_CI_APP_PRIVATE_KEY` (la GitHub App « PrestAI CI », installée
sur ce dépôt, lit prestai-ci, prestai-install et prestaicore, privés) ; `DOCKERHUB_USERNAME` et `DOCKERHUB_TOKEN`
facultatifs. Le dépôt est public : la CI des boutiques ne tourne jamais sur une pull request, seulement sur un push du
dépôt, à la demande ou sur un tag.

## Publier un catalogue

1. Les correctifs construits, prouvés sur les bancs (9.1.4 et 9.1.5), relus : une branche `feature/catalog-NNNN` avec
   les sources, `catalog/catalog.json` construit (numéro, date) et la section `## catalog-NNNN` de `CHANGELOG.md`.
2. Le script de publication, sur le PC qui a la clé principale : il vérifie la branche et l'empreinte du catalogue
   relu, signe `catalog/catalog.json` avec la clé principale (la phrase de passe est demandée, jamais écrite),
   vérifie la signature avec la partie publique de `keys/`, avance `main` sur la branche avec un commit de la
   signature, puis pose le tag `catalog-NNNN`.
3. `release.yml` vérifie tout, relance la CI complète et publie la release, marquée « latest ».

Un numéro ne sert qu'une fois : un catalogue corrigé prend le numéro suivant. Un catalogue ne retire jamais un
correctif qu'une boutique a pu appliquer sans dire ce qu'il devient (Core garde la sauvegarde et le retour arrière
de ce qui est appliqué).
