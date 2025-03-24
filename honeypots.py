import sys
import socket
import nmap
import time
import requests
from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLineEdit, QPushButton, QTextEdit, QLabel

class HoneypotDetectorApp(QWidget):
    def __init__(self):
        super().__init__()

        
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Détecteur de Honeypot')

        # Création des éléments graphiques
        self.layout = QVBoxLayout()

        self.label = QLabel('Entrez l\'IP ou le domaine à analyser :', self)
        self.layout.addWidget(self.label)

        self.input_ip = QLineEdit(self)
        self.layout.addWidget(self.input_ip)

        self.scan_button = QPushButton('Lancer le scan', self)
        self.scan_button.clicked.connect(self.detect_honeypot)
        self.layout.addWidget(self.scan_button)

        # Label d'état
        self.status_label = QLabel('Status : Prêt', self)
        self.layout.addWidget(self.status_label)

        self.text_output = QTextEdit(self)
        self.text_output.setReadOnly(True)
        self.layout.addWidget(self.text_output)

        self.setLayout(self.layout)
        self.resize(500, 400)
        self.show()

    def scan_ports(self, target):
        """Scanne les ports pour détecter des services suspects."""
        scanner = nmap.PortScanner()
        self.text_output.append(f"Scanning {target}...\n")
        scanner.scan(target, arguments="-p 22,23,80,443,3306,8080,4433,53,8888 -sV --open")
        honeypot_suspects = []

        for host in scanner.all_hosts():
            for port in scanner[host]['tcp']:
                service = scanner[host]['tcp'][port]['name']
                banner = scanner[host]['tcp'][port].get('product', 'N/A')
                self.text_output.append(f" - Port {port} ouvert ({service}) - {banner}\n")
                if service in ['cowrie', 'kippo', 'dionaea', 'snort', 'ssh', 'telnet']:
                    honeypot_suspects.append((host, port, service, banner))

        return honeypot_suspects

    def check_latency(self, target, port):
        """Mesure la latence pour détecter un honeypot."""
        start = time.time()
        try:
            with socket.create_connection((target, port), timeout=3):
                pass
        except (socket.timeout, ConnectionRefusedError):
            return None
        return time.time() - start

    def check_http_headers(self, target, port):
        """Analyse les en-têtes HTTP pour identifier des anomalies ou des messages typiques de honeypots."""
        try:
            response = requests.get(f'http://{target}:{port}', timeout=3)
            self.text_output.append(f"Réponse HTTP de {target}:{port} - Code de statut: {response.status_code}\n")
            self.text_output.append(f"En-têtes HTTP : {response.headers}\n")
            
            # Explications
            explanation = ""
            if 'Server' in response.headers:
                explanation += f" - Le header 'Server' indique un serveur : {response.headers['Server']}. Cela peut être une piste si c'est un serveur configuré pour imiter un autre service réel.\n"
            if 'X-Powered-By' in response.headers:
                explanation += f" - Le header 'X-Powered-By' montre : {response.headers['X-Powered-By']}. Cela peut indiquer un serveur web configuré de manière particulière.\n"
            
            if explanation:
                self.text_output.append(f"Explication des en-têtes : {explanation}\n")
            
            return response.headers
        except requests.exceptions.RequestException as e:
            self.text_output.append(f"Erreur de requête HTTP: {e}\n")
            return None

    def analyze_honeypot(self, suspects):
        """Analyse les résultats du scan et décide si c'est un honeypot ou non."""
        honeypot_detected = False
        for host, port, service, banner in suspects:
            explanation = ""
            if service in ['cowrie', 'kippo', 'dionaea', 'snort']:
                honeypot_detected = True
                explanation += f" - Service suspect détecté : {service}. Ce service est typiquement associé à des honeypots.\n"
            
            if port == 22 or port == 23:
                explanation += f" - Port {port} ouvert (SSH/Telnet). Ces ports sont fréquemment utilisés pour les honeypots.\n"
            
            if explanation:
                self.text_output.append(f"⚠️ {host}:{port} - Honeypot détecté (Explication: {explanation})\n")
            
        if not honeypot_detected:
            self.text_output.append("✅ Aucune anomalie détectée, pas de honeypot trouvé.\n")
        return honeypot_detected

    def detect_honeypot(self):
        """Détecte un honeypot en scannant l'IP donnée."""
        target = self.input_ip.text()
        self.text_output.clear()
        self.status_label.setText("Status : Scan en cours...")
        self.scan_button.setEnabled(False)  
        self.text_output.append(f"Détection des honeypots pour {target}...\n")
        
        
        suspects = self.scan_ports(target)

        for host, port, service, banner in suspects:
            latency = self.check_latency(host, port)
            if latency and latency > 0.5:
                self.text_output.append(f"⚠️ {host}:{port} pourrait être un honeypot (Service: {service}, Latence: {latency:.2f}s)\n")
            else:
                self.text_output.append(f"✅ {host}:{port} semble légitime.\n")
            
            if port == 80 or port == 443:
                headers = self.check_http_headers(host, port)
                if headers and 'Server' in headers and 'nginx' in headers['Server'].lower():
                    self.text_output.append(f"⚠️ {host}:{port} - Honeypot probable avec Nginx comme serveur web.\n")
                elif headers and 'X-Powered-By' in headers.get('X-Powered-By', '').lower():
                    self.text_output.append(f"⚠️ {host}:{port} - Potential honeypot détecté via 'X-Powered-By'.\n")
        
        
        honeypot = self.analyze_honeypot(suspects)

        if honeypot:
            self.status_label.setText("Status : Honeypot détecté.")
        else:
            self.status_label.setText("Status : Pas de Honeypot détecté.")
        
        self.scan_button.setEnabled(True)  

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = HoneypotDetectorApp()
    sys.exit(app.exec())
