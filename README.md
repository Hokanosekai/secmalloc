# Sec-Malloc

## Introduction

Ce projet est un allocateur mémoire sécurisé. L'implémentation est basée sur un allocateur de mémoire dynamique (heap) qui est sécurisé contre les attaques de type `heap overflow` et `double free`.

L'implémentation doit être capable de gérer les appels aux fonctions `malloc`, `free`, `calloc` et `realloc` de la librairie standard C.

## Architecture

L'implémentation est basée sur une heap qui est divisée en deux pools :

- Un pool de métadonnées: contenants les informations sur les blocs alloués (taille, adresse, etc.) implémenté sous forme de liste chaînée
- Un pool de données: contenant les données allouées

```raw
+-----------------+
|     Metapool    |
+-----------------+
|                 |
|      Empty      |
|                 |
+-----------------+
|                 |
|     Datapool    |
|                 |
+-----------------+
```

## Fonctionalités

- Double pool (métadonnées et données)
- Canary randomisé
- Variables d'environement
- Fichier de log
- Détection des heap overflow
- Détection des double free
- Détection des memory leaks
- Padding sur 16 bytes

## Compilation

Le projet est compilé à l'aide de `make`. Il est possible de compiler le projet en tant que librairie dynamique ou statique via les commandes suivantes :

```bash
make clean dynamic

make clean static
```

## Usage

La libraire (si elle est utilisée dynamiquement) n'a pas besoin d'être incluse dans le code. Le simple fait d'appeller les méthodes `malloc`, `free`, `calloc` et `realloc` et lançant l'éxécutable compilé avec la variable `LD_PRELOAD` contenant le `.so` de la librairie permet de rediriger les appels vers l'allocateur sécurisé.

```bash
LD_PRELOAD=./libmy_secmalloc.so ./my_executable
```

### Environnement

Afin de controller le fonctionnement de l'allocateur mémoire, il est possible de définir des variables d'environnement.

Les variables disponibles sont :

| Nom | Valeur par défaut | Usage |
| --- | ---               | ---   |
| MSM_OUTPUT | `NULL`      | Définit le fichier de log de l'implémentation, si il est a `NULL` aucun fichier ne sera créé. |
| MSM_DEBUG | `0` | Définit le niveau de debug de l'implémentation, le debug est inscrit dans le fichier de log. `0` pas de debug, `1` debug des informations basiques, `2` debug plus poussé, `3` debug encore plus poussé  |
| MSM_PAGE_SIZE | `4096` | Définit la taille des pages de la heap (data pool) |
| MSM_DEBUG_PAGE_SIZE | `16` | Définit la taille des pages de la heap (data pool) à afficher dans le debug |
| MSM_META_POOL_MAX_ENTRIES | `1e5` | Définit le nombre maximum d'entrées dans le pool de métadonnées |
| MSM_DATA_POOL_PAGES | `2` | Définit le nombre de pages dans le pool de données |

Pour définir une variable il suffit en fonction de son shell d'attribuer une valeur à une variable d'environnement. Par exemple pour définir le fichier de log :

```bash
export MSM_OUTPUT ./msm_report.log
```

```fish
set -Ux MSM_OUTPUT ./msm_report.log
```

On peut maintenant tester avec la commande `ls`

```bash
LD_PRELOAD=./libmy_secmalloc.so /usr/bin/ls
```

Normalement le fichier `msm_report.log` devrait être créé et devrait contenir les traces d'allocation et de déallocation de la heap.

### Debug

Comme définit plus haut il est possible de définir le niveau de debug de l'implémentation via la variable d'environnement `MSM_DEBUG`. Cette variable est un entier par défaut à `0` (pas de debug) et peut être définie à `1`, `2` ou `3`.

Il existe quatre niveau de debug possible :

| Niveau | Nom | Description |
| --- | --- | --- |
| 0 | none | pas de debug apparant |
| 1 | basic | debug des actions éffectuées et informations basic (pools et blocks) |
| 2 | avancé | debug des actions et d'informations plus poussées (pools et blocks) |
| 3 | all | debug des actions et des informattions (pools et blocks) avec dump de la mémoire. |

Pour définir le niveau de debug à `2` il suffit de définir la variable d'environnement `MSM_DEBUG` à `2`.

```bash
export MSM_DEBUG 2
```

## Tests et Coverage

> **Note**: Pour lancer les tests il est nécessaire d'avoir installé la librairie `Criterion` et `lcov` pour la couverture de code.

Les tests sont réalisés à l'aide de la librairie Criterion. Il est possible de les compiler puis de les éxécuter via :

```bash
make clean test
```

Il est aussi possible de générer un rapport de couverture de code via `gcov` et `lcov`.

```bashs
make clean coverage
```

Le rapport de couverture de code est généré dans le dossier `out` et est accessible via un navigateur web.

## Auteurs

- *Hokanosekai*
