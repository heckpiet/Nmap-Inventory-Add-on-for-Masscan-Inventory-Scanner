## 🚀 Erweiterung: Deep-Inventory (Nmap Add-on)

Dieses Projekt enthält nun ein Zusatz-Skript (`nmap_inventory_addon.py`), um die schnellen Ergebnisse von Masscan in ein detailliertes IT-Inventar zu verwandeln.

### Was macht das Add-on?
Während Masscan nur prüft, ob ein Port "offen" ist, geht dieses Add-on einen Schritt weiter:
- **DNS Lookup:** Löst IP-Adressen in Hostnamen auf.
- **OS Fingerprinting:** Identifiziert Betriebssysteme (Windows, Linux, IoT, etc.).
- **Service Detection:** Erkennt die genaue Version der laufenden Dienste (z.B. Apache 2.4.41).
- **Clustering:** Fasst alle Informationen pro IP in einer einzigen, übersichtlichen Zeile zusammen.

### Anwendung
Nachdem der Masscan-Lauf beendet wurde, findest du im `output`-Ordner die Datei `inventory_hosts.csv`. Starte das Add-on wie folgt:

```bash
python3 nmap_inventory_addon.py ./Masscan_Inventar_Scanner_[DATUM]/output/inventory_hosts.csv
