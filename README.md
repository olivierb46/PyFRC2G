# PyFRC2G

Scripts python de conversion de règles firewall **PfSense** et **OPNSense** en vision graphique des flux.

![pfsense](./img/convert-rules-to-graph.png)
![opnsense](./img/opnsense.png)

## 👋 Présentation

Le script a été codé pour répondre à deux objectifs :
* Avoir une vision graphique globale des règles firewall (une image vaut mille mots).
* Fournir des preuves permettant de répondre à des exigences de sécurité informatique édictées par les différents référentiels existants.

## ⚡ Caractéristiques

* Script basé sur **Python** (développé et testé sur GNU/Linux).
* Utilisation de l'API de pfSense fournie par [pfSense REST API Package](https://pfrest.org/).
* Utilisation de l'API intégrée d'OPNSense.
* Génération des flux graphiques avec la bibliothèque python **Graphviz**.
* Génération d'un fichier PDF A4 avec une page par interface.
* Distinction entre un VLAN/réseau de destination et un hôte de destination.
* Mapping des interfaces, des ports et des destinations.
* Coloration pour les actions PASS et BLOCK.
* Coloration pour les règles présentes mais désactivées (pfSense uniquement).
* Export possible du fichier PDF généré dans la preuve associée sur **[CISO Assistant](https://intuitem.com/fr/ciso-assistant/)** sous forme de révision afin de conserver l'historique des fichiers poussés.

## 💾 Installation

1. Prérequis

Installation des bibliothèques Python :

```Bash
pip install requests graphviz reportlab
```
2. pfSense
Installation de **pfSense REST API Package** : [https://github.com/jaredhendrickson13/pfsense-api?tab=readme-ov-file#quickstart](https://github.com/jaredhendrickson13/pfsense-api?tab=readme-ov-file#quickstart)

Une fois le paquet **pfSense REST API** installé, configurez la ou les interface(s) d'écoute sur **pfSense** puis générez une clé qui nous servira pour l'authentification à l'API. 

3. Configuration du script

Récupérez les fichiers **pyfrc2g.py** et **config.py** correspondant à votre passerelle (pfSense ou OPNSense).

Configurez l'**URL** de votre passerelle et vos **credentials** dans le fichier **pyfrc2g.py**.

Exemple avec pfSense :
```python
# --- CONFIG ---
PFS_URL = "https://pfs01.domaine.lan/api/v2/firewall/rules"
PFS_TOKEN = "VOTRE_CLE_GENEREE_AVEC_PFSENSE_REST_API"
PASSERELLE = "PFS01"
```
Pour OPNSense vous devez également renseigner le nom des interfaces car l'API ne permet pas de récupérer les règles qu'interface par interface (elles sont visibles sur *Interfaces > Assignations*)

Exemple avec OPNSense :
```python
OPNS_URL = "https://<OPNS_ADDRESS/api/firewall/filter/search_rule"
OPNS_SECRET = "<API_SECRET>"
OPNS_KEY = "<API_KEY>"
PASSERELLE = "<GW_NAME>"
(...)
# Déclaration des interfaces présentes sur OPNSense
INTERFACES = ["wan","lan","opt1"]
```
Configurez ensuite vos interfaces, les réseaux, les adresses des interfaces et les ports dans le fichier **config.py**.

Exemple avec pfSense :
```python
INTERFACE_MAP = {
    "wan": "WAN",
    "lan": "ADMINISTRATION",
    "opt1": "LAN",
    "opt2": "DMZ"
}

NET_MAP = {
    "wan": "WAN SUBNET",
    "lan": "ADMINISTRATION SUBNET",
    "opt1": "LAN SUBNET",
    "opt2": "DMZ SUBNET"
}

ADDRESS_MAP = {
    "wan:ip": "WAN ADDRESS",
    "lan:ip": "ADMINISTRATION ADDRESS",
    "opt1:ip": "LAN ADDRESS",
    "opt2:ip": "DMZ ADDRESS"
}

PORT_MAP = {
    "WEB_ACCESS": "80/443"
}
```
Pour OPNSense c'est un peu particulier. Par exemple dans pfSense quand une règle est à destination de tous les réseaux, il est indiqué "destination: Any". Avec OPNSense cela sera :
```
Destination:
  any: 1
```

J'ai donc déclaré dans config.py `"1" : "Any"` afin de renseigner *Any* dans la source et la destination sur le flux graphique.

```python
# --- TABLE DE CORRESPONDANCE POUR LES INTERFACES ---
INTERFACE_MAP = {
    "wan": "WAN",
    "lan": "LAN",
    "opt1": "DMZ01",
    "(self)": "All interfaces",
    "(em0)": "WAN",
    "1": "Any",
    "<sshlockout>": "IP bannies après trop de tentatives SSH/Console Web",
    "<virusprot>": "IP bannies après comportement suspect"
}

# --- TABLE DE CORRESPONDANCE POUR LES RESEAUX ---
NET_MAP = {
    "wan": "WAN SUBNET",
    "lan": "LAN SUBNET",
    "opt1": "DMZ01 SUBNET",
    "(self)": "All interfaces",
    "1": "Any"
}
(...)
```

## 🚀 Utilisation

1. Utilisation de base

Lancez le script **pyfrc2g.py**. Le script génèrera alors un fichier final PDF (après être passé par plusieurs fichiers intermédiaires qui sont supprimés une fois l'exécution du script terminée). Chaque page est nommée avec le nom de la passerelle et l'interface dans le répertoire fin de faciliter la navigation dans le fichier.

Si aucune règle n'a été ajoutée ou modifiée, le script ne regénère pas de fichier PDF (le script s'appuie sur comparaison de la somme md5sum entre la version précédent du CSV générée et la version en cours).

2. Utilisation avec CISO Assistant

Récupérez les fichiers **pyfrc2g-ciso_assist.py**, **config.py** et **md5sum.txt** correspondant à votre passerelle (pfSense ou OPNSense).

Configurez les paramètres d'accès à votre passerelle comme vu plus haut puis renseignez la partie CISO Assistant :
```python
# CISO Assistant
CISO_URL = "https://<CISO_ASSISTANT_ADDRESS>"
CISO_TOKEN = "<CISO_ASSISTANT_TOKEN>"
CISO_EVIDENCE = f"{CISO_URL}/api/evidences/<EVIDENCE_ID>/upload/"
```

3. Remarques
* Lors de la récupération des hôtes de destination, l'API de pfSense ne permet pas de connaitre le réseau dans lequel se situe celui-ci. J'ai donc commenté mes hôtes de destination sur pfSense en renseignant dans quel VLAN était celui-ci.
* Pour les hôtes de destination se situant en dehors de mon infrastructure interne, j'ai renseigné dans pfSense *EXT_* devant chaque nom d'alias de ces hôtes.
* OPNSense expose à travers son API les règles de manière complètement différente de celle de pfSense. À ce jour je n'ai pas trouvé comment récupérer les règles désactivées. Les règles flottantes auto-générées ne sont également pas simples à récupérer.

## 📝 Todo
* Améliorer le code (je ne suis pas dev et ça se voit sur le côté bordélique).
* Automatiser le script avec génération des graphiques uniquement pour les règles ayant changées.
* Notification des admins quand génération des graphiques.
* Insérer le VLAN de destination devant un hôte de destination.
* ~~Faire la même chose avec OPNSense~~.
* ~~Envoyez les preuves dans [CISO Assistant](https://intuitem.com/fr/ciso-assistant/)~~.
* Reprendre les horodatages sur la création/modification des règles ainsi que l'auteur.
