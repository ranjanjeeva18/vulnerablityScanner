import sys
import time
from PyQt6.QtWidgets import QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QLineEdit, QTextEdit
from PyQt6.QtCore import QThread, pyqtSignal, QPropertyAnimation, QRect
from zapv2 import ZAPv2

class VulnerabilityScanner:
    def __init__(self, api_key, zap_url='http://localhost:8080'):
        self.zap = ZAPv2(apikey=api_key, proxies={'http': zap_url, 'https': zap_url})

    def scan(self, target):
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target

        print(f'Starting scan on: {target}')
        self.zap.urlopen(target)
        time.sleep(2)

        scan_id = self.zap.ascan.scan(target)
        print('Active scan started...')

        while True:
            scan_status = int(self.zap.ascan.status(scan_id))
            print(f'Scan progress: {scan_status}%')
            if scan_status >= 100:
                break
            time.sleep(5)

        print('Scan completed!')

        alerts = self.zap.core.alerts(baseurl=target)
        results = [{'alert': alert['alert'], 'risk': alert['risk'], 'url': alert['url']} for alert in alerts]
        return results

class ScannerThread(QThread):
    results_signal = pyqtSignal(list)
    finished_signal = pyqtSignal()

    def __init__(self, target, api_key):
        super().__init__()
        self.target = target
        self.api_key = api_key
        self._running = True

    def run(self):
        scanner = VulnerabilityScanner(api_key=self.api_key)
        results = scanner.scan(self.target)
        if self._running:
            self.results_signal.emit(results)
        self.finished_signal.emit()

    def stop(self):
        self._running = False

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Vulnerability Scanner')

        layout = QVBoxLayout()

        self.url_input = QLineEdit(self)
        self.url_input.setPlaceholderText('Enter URL or IP Address')
        layout.addWidget(self.url_input)

        self.scan_button = QPushButton('Start Scan', self)
        self.stop_button = QPushButton('Stop Scan', self)
        self.scan_button.clicked.connect(self.start_scan)
        self.stop_button.clicked.connect(self.stop_scan)
        layout.addWidget(self.scan_button)
        layout.addWidget(self.stop_button)

        self.results_area = QTextEdit(self)
        self.results_area.setReadOnly(True)
        layout.addWidget(self.results_area)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.scanner_thread = None

    def start_scan(self):
        target = self.url_input.text()
        if not target:
            self.results_area.setText('Enter Valid URL or IP address')
            return

        self.results_area.setText('Scanning...\n')
        api_key = 'h2esg7id0cuulgsioe6fukq1df'  # Replace with your actual API key
        self.scanner_thread = ScannerThread(target, api_key)
        self.scanner_thread.results_signal.connect(self.display_results)
        self.scanner_thread.finished_signal.connect(self.scan_finished)
        self.scanner_thread.start()

    def stop_scan(self):
        if self.scanner_thread:
            self.scanner_thread.stop()  # Call stop method
            self.results_area.append('Scanning Stopped')

    def display_results(self, results):
        if not results:
            self.results_area.append('No vulnerabilities found.')
        else:
            for alert in results:
                self.results_area.append(f'Alert: {alert["alert"]}, Risk: {alert["risk"]}, URL: {alert["url"]}')

        # Animate the results area to fade in
        self.animate_results_area()

    def scan_finished(self):
        self.results_area.append('Scan finished.')
        # Animate the results area to fade in
        self.animate_results_area()

    def animate_results_area(self):
        # Create a property animation for the results area
        animation = QPropertyAnimation(self.results_area, b"geometry")
        animation.setDuration(500)  # Duration in milliseconds
        animation.setStartValue(QRect(self.results_area.x(), self.results_area.y(), self.results_area.width(), 0))
        animation.setEndValue(QRect(self.results_area.x(), self.results_area.y(), self.results_area.width(), self.results_area.height()))
        animation.start()

        # Optionally, you can also change the opacity for a fade effect
        self.results_area.setStyleSheet("QTextEdit { opacity: 0; }")
        fade_in_animation = QPropertyAnimation(self.results_area, b"windowOpacity")
        fade_in_animation.setDuration(500)
        fade_in_animation.setStartValue(0)
        fade_in_animation.setEndValue(1)
        fade_in_animation.start()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.resize(600, 400)
    window.show()
    sys.exit(app.exec())
