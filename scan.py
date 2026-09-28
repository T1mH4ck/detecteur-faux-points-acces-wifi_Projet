import subprocess

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

if __name__ == "__main__":
    texte = scan_networks()
    for r in extraire_reseaux(texte):
        print(r["ssid"], "-", r["bssid"])