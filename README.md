# Honeypot Detector

## Description

Ce projet permet de détecter la présence de honeypots (des pièges pour détecter les attaques) sur des sites web ou des adresses IP. Il utilise la bibliothèque **Nmap** pour scanner les ports, ainsi que des vérifications des en-têtes HTTP pour détecter des indices typiques de honeypots. Ce programme est conçu pour être utilisé avec une interface graphique **PySide6**.

## Fonctionnalités

- **Scan de ports** : Scanne les ports ouverts sur une IP ou un domaine spécifié pour identifier des services suspects.
- **Analyse des en-têtes HTTP** : Vérifie les en-têtes HTTP pour identifier des anomalies et des indices de honeypots.
- **Détection de honeypots** : Analyse les résultats pour déterminer si un service est potentiellement un honeypot.
- **Interface graphique** : Une interface simple pour entrer une adresse IP ou un domaine à scanner et afficher les résultats.

## Prérequis

Avant de pouvoir utiliser l'application, vous devez installer certains outils et bibliothèques.

### Outils nécessaires

- **Python 3.x** (version recommandée : 3.8 ou plus récente)
- **Nmap** : Un outil de scan de ports réseau. Vous pouvez l'installer sur [le site officiel de Nmap](https://nmap.org/download.html).
  
  **Sur Ubuntu/Debian** :  
  ```bash
  sudo apt-get install nmap

- Sur Windows : Téléchargez et installez Nmap depuis le site officiel.

- PySide6 : Pour l'interface graphique. Vous pouvez installer PySide6 avec pip :

- pip install PySide6

**Requests : Bibliothèque pour envoyer des requêtes HTTP afin de vérifier les en-têtes des sites web**

- pip install requests

## Étapes d'installation
- Clonez ce projet depuis GitHub
- Installez les dépendances requises
- puis le lancer via cmd

### Contribuer
- Si vous souhaitez contribuer à ce projet, vous pouvez :

- Forker le projet.

- Cloner votre fork.

- Créer une nouvelle branche 

### Auteurs
**cgtzname - Développeur principal.**

# Ce projet est sous licence MIT


# Ce projet est à des fins éducatives uniquement.  
# L'utilisation de cet outil pour accéder de manière non autorisée à des systèmes ou pour toute activité illégale est strictement interdite. je vous encourage à utiliser cet outil dans un environnement contrôlé, tel qu'un laboratoire ou un réseau privé, et à respecter les lois et régulations en vigueur dans votre pays. 
