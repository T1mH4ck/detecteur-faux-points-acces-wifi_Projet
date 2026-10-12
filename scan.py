import subprocess
import json
import os

def charger_reseaux_connus():
    dossier = os.path.dirname(os.path.abspath(__file__))
    chemin = os.path.join(dossier, "reseaux_connus.json")
    with open(chemin, "r", encoding="utf-8") as f:
        return json.load(f)

def scan_networks():
    result = subprocess.run(
        ["netsh", "wlan", "show", "networks", "mode=bssid"],
        capture_output=True, text=True, encoding="utf-8"
    )
    return result.stdout

def extraire_reseaux(texte):
    reseaux = []
    ssid_actuel = None
    for ligne in texte.splitlines():
        ligne = ligne.strip()
        if ligne.startswith("SSID"):
            ssid_actuel = ligne.split(":", 1)[1].strip()
        elif ligne.startswith("BSSID"):
            bssid = ligne.split(":", 1)[1].strip()
            reseaux.append({"ssid": ssid_actuel, "bssid": bssid})
    return reseaux

def detecter_anomalies(reseaux, reseaux_connus):
    alertes = []
    for r in reseaux:
        ssid = r["ssid"]
        bssid = r["bssid"].lower()
        if ssid in reseaux_connus:
            macs_ok = [m.lower() for m in reseaux_connus[ssid]]
            if bssid not in macs_ok:
                alertes.append("ALERTE : " + ssid + " détecté avec une MAC inconnue (" + bssid + ")")
    return alertes

if __name__ == "__main__":
    reseaux_connus = charger_reseaux_connus()
    texte = scan_networks()
    reseaux = extraire_reseaux(texte)
    for r in reseaux:
        print(r["ssid"], "-", r["bssid"])
    alertes = detecter_anomalies(reseaux, reseaux_connus)
    if alertes:
        for a in alertes:
            print(a)
    else:
        print("Aucune anomalie détectée")