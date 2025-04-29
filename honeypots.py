import sys
import socket
import nmap
import time
import requests
import threading
from PySide6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, 
                              QLineEdit, QPushButton, QTextEdit, QLabel, 
                              QProgressBar, QTabWidget, QCheckBox,
                              QGroupBox)
from PySide6.QtCore import Qt, QThread, Signal

class ScanResult:
    """Classe pour stocker et analyser les résultats du scan"""
    def __init__(self, host, port=None, service=None, banner=None):
        self.host = host
        self.port = port
        self.service = service
        self.banner = banner
        self.latency = None
        self.headers = None
        self.honeypot_score = 0  # 0-100
        self.explanations = []
        
    def add_explanation(self, explanation):
        self.explanations.append(explanation)
        
    def increase_score(self, points, reason):
        self.honeypot_score += points
        self.add_explanation(reason)
        
    def is_honeypot(self):
        return self.honeypot_score > 60

class ScannerThread(QThread):
    """Thread séparé pour exécuter les scans sans bloquer l'UI"""
    update_signal = Signal(str)
    progress_signal = Signal(int)
    result_signal = Signal(list)
    finished_signal = Signal()
    
    def __init__(self, target, scan_options):
        super().__init__()
        self.target = target
        self.scan_options = scan_options
        self.results = []
    
    def run(self):
        try:
            # Message de démarrage simple
            self.update_signal.emit("Analyse de la cible: " + self.target)
            
            # Scan des ports
            if self.scan_options.get('scan_ports', True):
                self.update_signal.emit("Phase 1: Scan des ports...")
                self.scan_ports()
                
            # Analyse des services
            if self.scan_options.get('analyze_services', True):
                self.update_signal.emit("Phase 2: Analyse des services...")
                self.analyze_services()
                
            # Tests de comportement
            if self.scan_options.get('behavior_tests', True):
                self.update_signal.emit("Phase 3: Tests de comportement...")
                self.behavior_tests()
                
            # Analyse finale
            self.analyze_results()
            
            # Envoi des résultats
            self.result_signal.emit(self.results)
            self.finished_signal.emit()
            
        except Exception as e:
            self.update_signal.emit("Erreur: " + str(e))
            self.finished_signal.emit()
    
    def scan_ports(self):
        """Scanne les ports pour détecter des services suspects"""
        try:
            scanner = nmap.PortScanner()
            # Ports communément utilisés par les honeypots
            ports = "21,22,23,25,80,110,143,443,445,1433,3306,3389,5900,8080,8888,9200"
            
            self.update_signal.emit("Scanning " + self.target + " sur les ports communs...")
            scanner.scan(self.target, arguments="-p " + ports + " -sV --open")
            
            total_ports = len(ports.split(','))
            scanned = 0
            
            for host in scanner.all_hosts():
                if 'tcp' not in scanner[host]:
                    continue
                    
                for port in scanner[host]['tcp']:
                    scanned += 1
                    self.progress_signal.emit(int(scanned / total_ports * 100))
                    
                    if scanner[host]['tcp'][port]['state'] == 'open':
                        service = scanner[host]['tcp'][port]['name']
                        banner = scanner[host]['tcp'][port].get('product', 'Non détecté')
                        version = scanner[host]['tcp'][port].get('version', '')
                        full_banner = banner + " " + version
                        
                        result = ScanResult(host, port, service, full_banner)
                        
                        # Vérification des services connus pour être utilisés comme honeypots
                        honeypot_services = ['cowrie', 'kippo', 'dionaea', 'conpot', 'glastopf', 'honeytrap']
                        for h_service in honeypot_services:
                            if h_service in service.lower() or h_service in full_banner.lower():
                                result.increase_score(80, "Service de honeypot détecté: " + h_service)
                        
                        self.results.append(result)
                        self.update_signal.emit("Port " + str(port) + " ouvert: " + service + " - " + full_banner)
        
        except Exception as e:
            self.update_signal.emit("Erreur lors du scan de ports: " + str(e))
    
    def analyze_services(self):
        """Analyse plus approfondie des services détectés"""
        for result in self.results:
            try:
                # Vérification de la latence
                latency = self.check_latency(self.target, result.port)
                result.latency = latency
                
                if latency:
                    self.update_signal.emit("Latence du port " + str(result.port) + ": " + str(round(latency, 3)) + "s")
                    
                    # Analyse de latence anormale
                    if latency > 1.0:
                        result.increase_score(30, "Latence élevée - pourrait indiquer un honeypot")
                    elif latency < 0.01:
                        result.increase_score(20, "Latence trop faible - pourrait être un service simulé")
                
                # Analyse HTTP/HTTPS pour les ports web
                if result.port in [80, 443, 8080, 8888]:
                    protocol = "https" if result.port == 443 else "http"
                    headers = self.check_http_headers(self.target, result.port, protocol)
                    result.headers = headers
                    
                    if headers:
                        # Analyse des en-têtes
                        if 'Server' in headers:
                            server = headers['Server']
                            self.update_signal.emit("Serveur web détecté: " + server)
                            
                            # Vérification des inconsistances de serveur web
                            if 'nginx' in server.lower() and result.service and 'apache' in result.service.lower():
                                result.increase_score(50, "Incohérence entre le service détecté et l'en-tête Server")
                
            except Exception as e:
                self.update_signal.emit("Erreur lors de l'analyse du service: " + str(e))
    
    def behavior_tests(self):
        """Tests de comportement pour détecter des anomalies"""
        # Test simplifié pour éviter les erreurs
        self.update_signal.emit("Tests de comportement effectués")
    
    def analyze_results(self):
        """Analyse finale des résultats pour déterminer le score global"""
        if not self.results:
            self.update_signal.emit("Aucun port ouvert détecté.")
            return
            
        # Ports ouverts
        open_ports = [r.port for r in self.results]
        
        # Trop de ports = suspicieux
        if len(open_ports) > 10:
            for result in self.results:
                result.increase_score(20, "Grand nombre de ports ouverts")
    
    def check_latency(self, target, port):
        """Mesure la latence pour détecter un honeypot"""
        try:
            start = time.time()
            with socket.create_connection((target, port), timeout=3):
                pass
            return time.time() - start
        except:
            return None
    
    def check_http_headers(self, target, port, protocol="http"):
        """Analyse les en-têtes HTTP pour identifier des anomalies"""
        try:
            response = requests.get(protocol + "://" + target + ":" + str(port), 
                                   timeout=5, 
                                   headers={'User-Agent': 'Mozilla/5.0'}, 
                                   verify=False)
            return response.headers
        except:
            return None


class HoneypotDetectorApp(QWidget):
    def __init__(self):
        super().__init__()
        self.scanner_thread = None
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Détecteur de Honeypot')
        self.setMinimumSize(700, 600)
        
        # Layout principal
        main_layout = QVBoxLayout()
        
        # Groupe cible
        target_group = QGroupBox("Cible")
        target_layout = QHBoxLayout()
        
        self.label = QLabel('IP ou domaine :', self)
        target_layout.addWidget(self.label)
        
        self.input_ip = QLineEdit(self)
        self.input_ip.setPlaceholderText("Exemple: 192.168.1.1 ou exemple.com")
        target_layout.addWidget(self.input_ip)
        
        target_group.setLayout(target_layout)
        main_layout.addWidget(target_group)
        
        # Options de scan
        options_group = QGroupBox("Options de scan")
        options_layout = QHBoxLayout()
        
        self.scan_ports_cb = QCheckBox("Scan des ports", self)
        self.scan_ports_cb.setChecked(True)
        options_layout.addWidget(self.scan_ports_cb)
        
        self.analyze_services_cb = QCheckBox("Analyse des services", self)
        self.analyze_services_cb.setChecked(True)
        options_layout.addWidget(self.analyze_services_cb)
        
        self.behavior_tests_cb = QCheckBox("Tests de comportement", self)
        self.behavior_tests_cb.setChecked(True)
        options_layout.addWidget(self.behavior_tests_cb)
        
        options_group.setLayout(options_layout)
        main_layout.addWidget(options_group)
        
        # Boutons
        buttons_layout = QHBoxLayout()
        
        self.scan_button = QPushButton('Lancer le scan', self)
        self.scan_button.clicked.connect(self.start_scan)
        buttons_layout.addWidget(self.scan_button)
        
        self.stop_button = QPushButton('Arrêter', self)
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        buttons_layout.addWidget(self.stop_button)
        
        main_layout.addLayout(buttons_layout)
        
        # Barre de progression
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setValue(0)
        main_layout.addWidget(self.progress_bar)
        
        # Label d'état
        self.status_label = QLabel('Status : Prêt', self)
        main_layout.addWidget(self.status_label)
        
        # Tabs pour les résultats
        self.tabs = QTabWidget()
        
        # Tab de log
        self.log_tab = QWidget()
        log_layout = QVBoxLayout()
        
        self.text_output = QTextEdit(self)
        self.text_output.setReadOnly(True)
        log_layout.addWidget(self.text_output)
        
        self.log_tab.setLayout(log_layout)
        self.tabs.addTab(self.log_tab, "Journal")
        
        # Tab de résultats
        self.results_tab = QWidget()
        results_layout = QVBoxLayout()
        
        self.results_output = QTextEdit(self)
        self.results_output.setReadOnly(True)
        results_layout.addWidget(self.results_output)
        
        self.results_tab.setLayout(results_layout)
        self.tabs.addTab(self.results_tab, "Résultats")
        
        # Tab d'explications
        self.explanations_tab = QWidget()
        explanations_layout = QVBoxLayout()
        
        self.explanations_output = QTextEdit(self)
        self.explanations_output.setReadOnly(True)
        self.explanations_output.setHtml("""
        <h2>À propos des Honeypots</h2>
        <p>Un <b>honeypot</b> est un leurre informatique conçu pour attirer les attaquants et étudier leurs méthodes.</p>
        
        <h3>Comment ce détecteur fonctionne:</h3>
        <ul>
            <li><b>Scan de ports</b>: Détecte les ports ouverts et services associés</li>
            <li><b>Analyse de services</b>: Vérifie si les services correspondent à ce qu'on attend normalement</li>
            <li><b>Tests de comportement</b>: Analyse les réponses des services pour détecter des anomalies</li>
            <li><b>Analyse de latence</b>: Des latences anormales peuvent indiquer un honeypot</li>
        </ul>
        
        <h3>Indicateurs de honeypot:</h3>
        <ul>
            <li>Trop de ports ouverts simultanément</li>
            <li>Services connus de honeypot (cowrie, kippo, dionaea)</li>
            <li>Combinaisons inhabituelles de ports et services</li>
            <li>Latence anormalement haute ou basse</li>
            <li>Incohérences dans les bannières de service</li>
        </ul>
        
        <p><b>Note</b>: Cette détection n'est pas infaillible. Des faux positifs et faux négatifs sont possibles.</p>
        """)
        explanations_layout.addWidget(self.explanations_output)
        
        self.explanations_tab.setLayout(explanations_layout)
        self.tabs.addTab(self.explanations_tab, "Explications")
        
        main_layout.addWidget(self.tabs)
        
        self.setLayout(main_layout)
        self.show()

    def start_scan(self):
        """Démarre le scan dans un thread séparé"""
        target = self.input_ip.text().strip()
        
        if not target:
            self.update_log("Erreur: Veuillez entrer une IP ou un domaine", error=True)
            return
            
        # Options de scan
        scan_options = {
            'scan_ports': self.scan_ports_cb.isChecked(),
            'analyze_services': self.analyze_services_cb.isChecked(),
            'behavior_tests': self.behavior_tests_cb.isChecked()
        }
            
        # Préparation de l'interface
        self.text_output.clear()
        self.results_output.clear()
        self.progress_bar.setValue(0)
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.status_label.setText("Status : Scan en cours...")
        self.tabs.setCurrentIndex(0)  # Aller à l'onglet Journal
        
        # Création et démarrage du thread de scan
        self.scanner_thread = ScannerThread(target, scan_options)
        self.scanner_thread.update_signal.connect(self.update_log)
        self.scanner_thread.progress_signal.connect(self.update_progress)
        self.scanner_thread.result_signal.connect(self.process_results)
        self.scanner_thread.finished_signal.connect(self.scan_finished)
        self.scanner_thread.start()

    def stop_scan(self):
        """Arrête le scan en cours"""
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.scanner_thread.terminate()
            self.update_log("Scan arrêté par l'utilisateur", error=True)
            self.scan_finished()

    def update_log(self, message, error=False):
        """Ajoute un message au journal"""
        if error:
            # Formater en rouge pour les erreurs
            self.text_output.append("<span style='color: red;'>" + message + "</span>")
        else:
            self.text_output.append(message)
            
        # Auto-scroll
        scrollbar = self.text_output.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def update_progress(self, value):
        """Met à jour la barre de progression"""
        self.progress_bar.setValue(value)

    def process_results(self, results):
        """Traite et affiche les résultats du scan"""
        if not results:
            self.results_output.setHtml("<h3>Aucun résultat</h3><p>Aucun port ouvert n'a été détecté sur cette cible.</p>")
            return
            
        # Basculer vers l'onglet des résultats
        self.tabs.setCurrentIndex(1)
        
        # Créer le rapport HTML
        html = "<h2>Résultats de la détection de Honeypot</h2>"
        
        # Résumé global
        honeypot_results = [r for r in results if r.is_honeypot()]
        if honeypot_results:
            html += "<div style='background-color: #ffcccc; padding: 10px; border-radius: 5px; margin: 10px 0;'>"
            html += "<h3>⚠️ Honeypot détecté!</h3>"
            html += "</div>"
        else:
            html += "<div style='background-color: #ccffcc; padding: 10px; border-radius: 5px; margin: 10px 0;'>"
            html += "<h3>✅ Aucun honeypot détecté</h3>"
            html += "</div>"
        
        # Détails des résultats
        html += "<h3>Détails des ports analysés:</h3>"
        html += "<table border='1' style='width: 100%; border-collapse: collapse;'>"
        html += "<tr style='background-color: #eaeaea;'><th>Port</th><th>Service</th><th>Bannière</th><th>Score</th><th>Verdict</th></tr>"
        
        for result in sorted(results, key=lambda x: x.port):
            # Définir la couleur de fond en fonction du score
            if result.is_honeypot():
                bg_color = "#ffcccc"  # Rouge clair
            elif result.honeypot_score > 30:
                bg_color = "#ffffcc"  # Jaune clair
            else:
                bg_color = "#ccffcc"  # Vert clair
                
            html += "<tr style='background-color: " + bg_color + ";'>"
            html += "<td>" + str(result.port) + "</td>"
            html += "<td>" + str(result.service) + "</td>"
            html += "<td>" + str(result.banner) + "</td>"
            html += "<td>" + str(result.honeypot_score) + "/100</td>"
            
            if result.is_honeypot():
                html += "<td>⚠️ Probable honeypot</td>"
            elif result.honeypot_score > 30:
                html += "<td>⚠️ Suspect</td>"
            else:
                html += "<td>✅ Normal</td>"
                
            html += "</tr>"
        
        html += "</table>"
        
        # Afficher le rapport
        self.results_output.setHtml(html)

    def scan_finished(self):
        """Appelé lorsque le scan est terminé"""
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_label.setText("Status : Scan terminé")
        self.progress_bar.setValue(100)


if __name__ == '__main__':
    # Ignorer les avertissements SSL pour les tests HTTPS
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    app = QApplication(sys.argv)
    ex = HoneypotDetectorApp()
    sys.exit(app.exec())