#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Reanzap - Gelişmiş Ağ Tarama Aracı
"""

import sys
import os
import json
import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                            QComboBox, QTabWidget, QTextEdit, QTableWidget, 
                            QTableWidgetItem, QHeaderView, QMessageBox, 
                            QFileDialog, QSplitter, QTreeWidget, QTreeWidgetItem,
                            QProgressBar, QMenuBar, QMenu, QAction, QStatusBar,
                            QDialog, QFormLayout, QSpinBox, QCheckBox, QGroupBox,
                            QStyle)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize
from PyQt5.QtGui import QIcon, QFont, QPalette, QColor

# Ağ görselleştirme modülünü içe aktar
from network_visualizer import NetworkGraph
from scanner import PortScanner, SCAN_PROFILES
from language_manager import LanguageManager
from settings_dialog import SettingsDialog

class Language:
    """Dil yönetimi için sınıf"""
    def __init__(self):
        self.translations = {}
        self.current_language = "en"
        self.available_languages = {
            "en": "English",
            "tr": "Türkçe"
        }
        self.load_translations()
    
    def load_translations(self):
        """Load all translation files"""
        for lang_code in self.available_languages.keys():
            try:
                with open(f"translations/{lang_code}.json", "r", encoding="utf-8") as f:
                    self.translations[lang_code] = json.load(f)
            except Exception as e:
                print(f"Error loading {lang_code} translations: {e}")
                if lang_code == "en":
                    # If English translations fail to load, create basic translations
                    self.translations["en"] = {"error": "Translation Error"}
    
    def get_text(self, key):
        """Get translated text for a key"""
        try:
            # Split nested keys (e.g., "menu.file" -> ["menu", "file"])
            keys = key.split(".")
            value = self.translations[self.current_language]
            
            # Navigate through nested dictionary
            for k in keys:
                value = value[k]
            return value
        except Exception:
            # Fallback to English if translation not found
            try:
                keys = key.split(".")
                value = self.translations["en"]
                for k in keys:
                    value = value[k]
                return value
            except Exception:
                # Return key if no translation found
                return key
    
    def set_language(self, lang_code):
        """Set current language"""
        if lang_code in self.translations:
            self.current_language = lang_code
            return True
        return False
    
    def get_available_languages(self):
        """Get dictionary of available languages"""
        return self.available_languages

class ScanThread(QThread):
    """Tarama işlemini arka planda çalıştırmak için QThread sınıfı"""
    update_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    finished_signal = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, target, profile):
        super().__init__()
        self.target = target
        self.profile = profile
        self.scanner = PortScanner()
    
    def run(self):
        try:
            self.update_signal.emit(f"Tarama başlatılıyor: {self.target} {self.profile}")
            
            # İlerleme durumunu güncellemek için zamanlayıcı
            def update_progress():
                progress = self.scanner.update_progress()
                self.progress_signal.emit(int(progress))
            
            timer = QTimer()
            timer.timeout.connect(update_progress)
            timer.start(100)  # Her 100ms'de bir güncelle
            
            # Taramayı başlat
            results = self.scanner.scan(self.target, self.profile)
            
            timer.stop()
            self.update_signal.emit("Tarama tamamlandı!")
            self.finished_signal.emit(results)
        
        except Exception as e:
            self.error.emit(str(e))
    
    def stop(self):
        """Taramayı durdur"""
        if self.scanner:
            self.scanner.stop()


class ReanzapMainWindow(QMainWindow):
    """Ana uygulama penceresi"""
    
    def __init__(self):
        super().__init__()
        self.lang = Language()  # Initialize language support
        self.scan_history = []
        self.current_scan_thread = None
        self.scanner = None
        self.scan_thread = None
        self.scan_profiles = {
            "quick_scan": "-sV -T4 -O -F",
            "intense_scan": "-T4 -A -v",
            "intense_scan_udp": "-sS -sU -T4 -A -v",
            "intense_scan_all_tcp": "-p 1-65535 -T4 -A -v",
            "intense_scan_no_ping": "-T4 -A -v -Pn",
            "ping_scan": "-sn",
            "regular_scan": "-sV -T3 -O"
        }
        self.init_ui()
    
    def init_ui(self):
        """Kullanıcı arayüzünü oluştur"""
        self.setWindowTitle(self.lang.get_text("app_title"))
        self.setFixedSize(1200, 800)  # Sabit pencere boyutu
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowMaximizeButtonHint)  # Maximize butonunu kaldır
        
        # Menü çubuğu
        self.create_menu_bar()
        
        # Ana widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(5, 5, 5, 5)
        main_layout.setSpacing(5)
        
        # Üst panel - Hedef ve tarama kontrolü
        top_panel = QWidget()
        top_layout = QHBoxLayout(top_panel)
        top_layout.setContentsMargins(0, 0, 0, 0)
        
        target_label = QLabel(self.lang.get_text("main.target"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText(self.lang.get_text("main.target_placeholder"))
        
        self.scan_button = QPushButton(self.lang.get_text("main.scan"))
        self.scan_button.clicked.connect(self.start_scan)
        self.scan_button.setFixedWidth(100)
        
        self.stop_button = QPushButton(self.lang.get_text("main.stop"))
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        self.stop_button.setFixedWidth(100)
        
        top_layout.addWidget(target_label)
        top_layout.addWidget(self.target_input)
        top_layout.addWidget(self.scan_button)
        top_layout.addWidget(self.stop_button)
        
        # Ana içerik bölümü
        content_splitter = QSplitter(Qt.Horizontal)
        
        # Sol panel - Profil ve komut seçenekleri
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        
        # Profil seçimi
        profile_group = QGroupBox(self.lang.get_text("main.profile"))
        profile_group.setObjectName("profile_group")
        profile_layout = QVBoxLayout(profile_group)
        self.profile_combo = QComboBox()
        for profile_key in self.scan_profiles.keys():
            self.profile_combo.addItem(self.lang.get_text(f"scan_profiles.{profile_key}"), profile_key)
        profile_layout.addWidget(self.profile_combo)
        
        # Komut görüntüleme
        command_group = QGroupBox(self.lang.get_text("main.command"))
        command_group.setObjectName("command_group")
        command_layout = QVBoxLayout()
        command_layout.setContentsMargins(5, 5, 5, 5)
        self.command_display = QTextEdit()
        self.command_display.setReadOnly(True)
        self.command_display.setMaximumHeight(100)
        self.command_display.setFont(QFont("Courier New", 9))
        command_layout.addWidget(self.command_display)
        command_group.setLayout(command_layout)
        
        left_layout.addWidget(profile_group)
        left_layout.addWidget(command_group)
        left_layout.addStretch()
        
        # Orta panel - Sonuç sekmeleri
        self.result_tabs = QTabWidget()
        
        # Nmap çıktı sekmesi
        self.output_tab = QTextEdit()
        self.output_tab.setReadOnly(True)
        self.output_tab.setFont(QFont("Courier New", 9))
        
        # Portlar sekmesi
        self.ports_tab = QTableWidget()
        self.ports_tab.setColumnCount(5)
        self.ports_tab.setHorizontalHeaderLabels(["Port", "Protokol", "Durum", "Servis", "Sürüm"])
        header = self.ports_tab.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        
        # Host detayları sekmesi
        self.details_tab = QTextEdit()
        self.details_tab.setReadOnly(True)
        self.details_tab.setFont(QFont("Courier New", 9))
        
        # Topoloji sekmesi
        self.network_graph = NetworkGraph()
        
        # Güvenlik açıkları sekmesi
        self.vuln_tab = QTreeWidget()
        self.vuln_tab.setHeaderLabels(["Port", "Servis", "CVE ID", "Önem", "Açıklama"])
        self.vuln_tab.setColumnWidth(0, 80)  # Port
        self.vuln_tab.setColumnWidth(1, 100)  # Servis
        self.vuln_tab.setColumnWidth(2, 120)  # CVE ID
        self.vuln_tab.setColumnWidth(3, 80)  # Önem
        self.vuln_tab.setColumnWidth(4, 400)  # Açıklama
        
        # Sekmeleri ekle
        self.result_tabs.addTab(self.output_tab, self.lang.get_text("tabs.nmap_output"))
        self.result_tabs.addTab(self.ports_tab, self.lang.get_text("tabs.ports_hosts"))
        self.result_tabs.addTab(self.details_tab, self.lang.get_text("tabs.details"))
        self.result_tabs.addTab(self.network_graph, self.lang.get_text("tabs.topology"))
        self.result_tabs.addTab(self.vuln_tab, self.lang.get_text("tabs.vulnerabilities"))
        
        # Sağ panel - Host listesi
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        
        hosts_group = QGroupBox("Hosts")
        hosts_layout = QVBoxLayout()
        hosts_layout.setContentsMargins(5, 5, 5, 5)
        
        self.hosts_tree = QTreeWidget()
        self.hosts_tree.setHeaderLabels(["Hostlar"])
        self.hosts_tree.setIconSize(QSize(16, 16))
        self.hosts_tree.itemClicked.connect(self.show_host_details)
        
        hosts_layout.addWidget(self.hosts_tree)
        hosts_group.setLayout(hosts_layout)
        right_layout.addWidget(hosts_group)
        
        # Panelleri splitter'a ekle
        content_splitter.addWidget(left_panel)
        content_splitter.addWidget(self.result_tabs)
        content_splitter.addWidget(right_panel)
        
        # Splitter oranlarını ayarla
        content_splitter.setStretchFactor(0, 1)  # Sol panel
        content_splitter.setStretchFactor(1, 4)  # Orta panel
        content_splitter.setStretchFactor(2, 1)  # Sağ panel
        
        # İlerleme çubuğu
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setAlignment(Qt.AlignCenter)
        self.progress_bar.setMaximumHeight(15)
        
        # Ana düzene panelleri ekle
        main_layout.addWidget(top_panel)
        main_layout.addWidget(content_splitter)
        main_layout.addWidget(self.progress_bar)
        
        # Durum çubuğu
        status_bar = self.statusBar()
        status_bar.setFixedHeight(20)
        status_bar.showMessage(self.lang.get_text("main.ready"))
        
        # İlk profil seçeneğini ayarla
        self.update_command()
        
        # Zenmap temasını ayarla
        self.set_zenmap_theme()
    
    def create_menu_bar(self):
        """Menü çubuğunu oluştur"""
        menubar = self.menuBar()
        
        # Dosya menüsü
        file_menu = menubar.addMenu(self.lang.get_text("menu.file"))
        file_menu.setObjectName("file_menu")
        
        save_action = QAction(self.lang.get_text("menu.save_results"), self)
        save_action.setShortcut("Ctrl+S")
        save_action.triggered.connect(self.save_scan_results)
        file_menu.addAction(save_action)
        
        exit_action = QAction(self.lang.get_text("menu.exit"), self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Düzen menüsü
        edit_menu = menubar.addMenu(self.lang.get_text("menu.edit"))
        edit_menu.setObjectName("edit_menu")
        
        settings_action = QAction(self.lang.get_text("menu.settings"), self)
        settings_action.triggered.connect(self.show_settings)
        edit_menu.addAction(settings_action)
        
        # Language menu
        language_menu = menubar.addMenu(self.lang.get_text("menu.language"))
        language_menu.setObjectName("language_menu")
        for code, name in self.lang.get_available_languages().items():
            lang_action = QAction(name, self)
            lang_action.setData(code)
            lang_action.triggered.connect(self.change_language)
            language_menu.addAction(lang_action)
        
        # Yardım menüsü
        help_menu = menubar.addMenu(self.lang.get_text("menu.help"))
        help_menu.setObjectName("help_menu")
        
        about_action = QAction(self.lang.get_text("menu.about"), self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def set_zenmap_theme(self):
        """Zenmap temasını ayarla"""
        # Zenmap'in orijinal renk paleti
        palette = QPalette()
        base_color = QColor(238, 238, 238)  # Açık gri
        text_color = QColor(0, 0, 0)  # Siyah
        highlight_color = QColor(51, 153, 255)  # Mavi
        
        palette.setColor(QPalette.Window, base_color)
        palette.setColor(QPalette.WindowText, text_color)
        palette.setColor(QPalette.Base, Qt.white)
        palette.setColor(QPalette.AlternateBase, base_color)
        palette.setColor(QPalette.ToolTipBase, Qt.white)
        palette.setColor(QPalette.ToolTipText, text_color)
        palette.setColor(QPalette.Text, text_color)
        palette.setColor(QPalette.Button, base_color)
        palette.setColor(QPalette.ButtonText, text_color)
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Highlight, highlight_color)
        palette.setColor(QPalette.HighlightedText, Qt.white)
        
        self.setPalette(palette)
        
        # Stil sayfası
        self.setStyleSheet("""
            QMainWindow {
                background-color: #EEEEEE;
            }
            QMenuBar {
                background-color: #EEEEEE;
                border-bottom: 1px solid #CCCCCC;
            }
            QMenuBar::item {
                padding: 4px 8px;
                background-color: transparent;
            }
            QMenuBar::item:selected {
                background-color: #3399FF;
                color: white;
            }
            QMenu {
                background-color: #EEEEEE;
                border: 1px solid #CCCCCC;
            }
            QMenu::item:selected {
                background-color: #3399FF;
                color: white;
            }
            QTabWidget::pane {
                border: 1px solid #CCCCCC;
                background-color: white;
            }
            QTabBar::tab {
                background-color: #EEEEEE;
                border: 1px solid #CCCCCC;
                border-bottom: none;
                padding: 5px 10px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: white;
                border-bottom: 1px solid white;
            }
            QGroupBox {
                background-color: white;
                border: 1px solid #CCCCCC;
                border-radius: 3px;
                margin-top: 0.5em;
                padding-top: 0.5em;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px;
            }
            QPushButton {
                background-color: #EEEEEE;
                border: 1px solid #CCCCCC;
                border-radius: 2px;
                padding: 4px 15px;
            }
            QPushButton:hover {
                background-color: #E0E0E0;
            }
            QPushButton:pressed {
                background-color: #D0D0D0;
            }
            QLineEdit {
                border: 1px solid #CCCCCC;
                border-radius: 2px;
                padding: 3px;
                background-color: white;
            }
            QTextEdit {
                border: 1px solid #CCCCCC;
                background-color: white;
            }
            QTreeWidget {
                border: 1px solid #CCCCCC;
                background-color: white;
            }
            QTableWidget {
                border: 1px solid #CCCCCC;
                background-color: white;
                gridline-color: #EEEEEE;
            }
            QHeaderView::section {
                background-color: #EEEEEE;
                border: 1px solid #CCCCCC;
                border-left: none;
                padding: 4px;
            }
            QProgressBar {
                border: 1px solid #CCCCCC;
                border-radius: 2px;
                text-align: center;
                background-color: white;
            }
            QProgressBar::chunk {
                background-color: #3399FF;
            }
            QStatusBar {
                background-color: #EEEEEE;
                border-top: 1px solid #CCCCCC;
            }
        """)
    
    def show_settings(self):
        dialog = SettingsDialog(self)
        
        # Load current settings
        settings = {
            "language": self.lang.get_current_language(),
            "theme": "dark",  # Default theme
            "thread_count": 10,  # Default thread count
            "timeout": 5  # Default timeout
        }
        dialog.set_settings(settings)
        
        if dialog.exec_() == QDialog.Accepted:
            new_settings = dialog.get_settings()
            
            # Apply language change
            if new_settings["language"] != settings["language"]:
                self.lang.set_language(new_settings["language"])
                self.refresh_ui()
            
            # Apply theme change
            if new_settings["theme"] != settings["theme"]:
                if new_settings["theme"] == "dark":
                    self.set_zenmap_theme()
                else:
                    self.set_light_theme()
            
            # Apply scanner settings
            # TODO: Update scanner with new thread count and timeout
    
    def set_light_theme(self):
        palette = QPalette()
        palette.setColor(QPalette.Window, Qt.white)
        palette.setColor(QPalette.WindowText, Qt.black)
        palette.setColor(QPalette.Base, Qt.white)
        palette.setColor(QPalette.AlternateBase, QColor(240, 240, 240))
        palette.setColor(QPalette.ToolTipBase, Qt.white)
        palette.setColor(QPalette.ToolTipText, Qt.black)
        palette.setColor(QPalette.Text, Qt.black)
        palette.setColor(QPalette.Button, QColor(240, 240, 240))
        palette.setColor(QPalette.ButtonText, Qt.black)
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Link, QColor(0, 0, 255))
        palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        palette.setColor(QPalette.HighlightedText, Qt.white)
        self.setPalette(palette)
    
    def show_about(self):
        """Hakkında penceresini göster"""
        about_text = f"{self.lang.get_text('about.title')}\n\n"
        about_text += f"{self.lang.get_text('about.version')}\n"
        about_text += f"{self.lang.get_text('about.license')}\n\n"
        about_text += f"{self.lang.get_text('about.description')}"
        
        QMessageBox.about(self, self.lang.get_text("menu.about"), about_text)
    
    def update_command(self):
        """Komut satırını güncelle"""
        target = self.target_input.text().strip()
        profile_key = self.profile_combo.currentData()
        if not profile_key:
            profile_key = list(self.scan_profiles.keys())[0]
        
        command = f"nmap {self.scan_profiles[profile_key]}"
        if target:
            command += f" {target}"
        
        self.command_display.setText(command)
    
    def show_host_details(self, item):
        """Host detaylarını göster"""
        host = item.text(0)
        if not host:
            return
        
        # Host detaylarını al
        for scan in self.scan_history:
            if host in scan:
                host_data = scan[host]
                
                # Detay metnini oluştur
                details = []
                details.append(f"Host: {host}")
                
                # Hostname
                hostnames = host_data.get("hostnames", [])
                if hostnames and hostnames[0].get("name"):
                    details.append(f"Hostname: {hostnames[0].get('name')}")
                
                # Durum
                status = host_data.get("status", {}).get("state", "unknown")
                details.append(f"Status: {status}")
                
                # İşletim sistemi
                osmatch = host_data.get("osmatch", [])
                if osmatch:
                    details.append(f"OS: {osmatch[0].get('name', 'Unknown')}")
                
                # MAC adresi
                addresses = host_data.get("addresses", {})
                if "mac" in addresses:
                    details.append(f"MAC: {addresses['mac']}")
                
                # Portları listele
                details.append("\nOpen Ports:")
                
                # TCP portları
                tcp_ports = host_data.get("tcp", {})
                for port, port_data in tcp_ports.items():
                    if port_data.get("state") == "open":
                        service = port_data.get("name", "unknown")
                        product = port_data.get("product", "")
                        version = port_data.get("version", "")
                        details.append(f"{port}/tcp\t{service}\t{product} {version}")
                
                # UDP portları
                udp_ports = host_data.get("udp", {})
                for port, port_data in udp_ports.items():
                    if port_data.get("state") == "open":
                        service = port_data.get("name", "unknown")
                        product = port_data.get("product", "")
                        version = port_data.get("version", "")
                        details.append(f"{port}/udp\t{service}\t{product} {version}")
                
                # Detayları göster
                self.details_tab.setText("\n".join(details))
                break
    
    def start_scan(self):
        """Tarama işlemini başlat"""
        target = self.target_input.text().strip()
        
        if not target:
            QMessageBox.warning(self, self.lang.get_text("messages.error"),
                              self.lang.get_text("messages.no_target"))
            return
        
        # Önceki tarama varsa durdur
        if self.current_scan_thread and self.current_scan_thread.isRunning():
            self.stop_scan()
        
        # Tarama thread'ini başlat
        self.current_scan_thread = ScanThread(target, self.profile_combo.currentText())
        self.current_scan_thread.update_signal.connect(self.update_status)
        self.current_scan_thread.progress_signal.connect(self.update_progress)
        self.current_scan_thread.finished_signal.connect(self.process_scan_results)
        self.current_scan_thread.error.connect(self.scan_error)
        
        # UI'ı güncelle
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.output_tab.clear()
        self.progress_bar.setValue(0)
        self.statusBar().showMessage(self.lang.get_text("main.scanning"))
        
        # Thread'i başlat
        self.current_scan_thread.start()
    
    def stop_scan(self):
        """Taramayı durdur"""
        if self.current_scan_thread and self.current_scan_thread.isRunning():
            self.current_scan_thread.stop()
            self.current_scan_thread.wait()
            self.update_status(self.lang.get_text("main.scan_stopped"))
            self.scan_button.setEnabled(True)
            self.stop_button.setEnabled(False)
    
    def update_status(self, message):
        """Durum mesajını güncelle"""
        self.statusBar().showMessage(message)
        self.output_tab.append(message)
    
    def update_progress(self, value):
        """İlerleme çubuğunu güncelle"""
        self.progress_bar.setValue(value)
    
    def process_scan_results(self, results):
        """Tarama sonuçlarını işle"""
        # UI'ı güncelle
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setValue(100)
        self.statusBar().showMessage(self.lang.get_text("main.scan_completed"))
        
        # Sonuçları geçmişe ekle
        self.scan_history.append(results)
        
        # Host listesini temizle
        self.hosts_tree.clear()
        
        # Nmap çıktısını göster
        self.output_tab.setText(self.current_scan_thread.scanner.get_nmap_last_output())
        
        # Port tablosunu temizle
        self.ports_tab.setRowCount(0)
        
        # Güvenlik açıkları sekmesini temizle
        self.vuln_tab.clear()
        
        # Her host için sonuçları işle
        for ip, host_data in results.items():
            # Host ağacına ekle
            status = host_data.get("status", {}).get("state", "unknown")
            host_item = QTreeWidgetItem([ip])
            
            # Host durumuna göre simge ekle
            if status == "up":
                host_item.setIcon(0, self.style().standardIcon(QStyle.SP_MediaPlay))
            else:
                host_item.setIcon(0, self.style().standardIcon(QStyle.SP_MediaStop))
            
            self.hosts_tree.addTopLevelItem(host_item)
            
            # Port tablosuna portları ekle
            ports = host_data.get("ports", {})
            for port, data in ports.items():
                if data.get("state") == "open":
                    row = self.ports_tab.rowCount()
                    self.ports_tab.insertRow(row)
                    self.ports_tab.setItem(row, 0, QTableWidgetItem(str(port)))
                    self.ports_tab.setItem(row, 1, QTableWidgetItem(data.get("name", "")))
                    self.ports_tab.setItem(row, 2, QTableWidgetItem(data.get("state", "")))
                    self.ports_tab.setItem(row, 3, QTableWidgetItem(data.get("product", "")))
                    self.ports_tab.setItem(row, 4, QTableWidgetItem(data.get("version", "")))
            
            # Güvenlik açıklarını ekle
            vulnerabilities = host_data.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                vuln_item = QTreeWidgetItem([
                    str(vuln.get("port", "")),
                    vuln.get("service", ""),
                    vuln.get("cve_id", ""),
                    vuln.get("severity", ""),
                    vuln.get("description", "")
                ])
                
                # Önem derecesine göre renk ver
                severity = vuln.get("severity", "").lower()
                if severity == "critical":
                    vuln_item.setBackground(3, QColor(255, 0, 0, 100))  # Kırmızı
                elif severity == "high":
                    vuln_item.setBackground(3, QColor(255, 165, 0, 100))  # Turuncu
                elif severity == "medium":
                    vuln_item.setBackground(3, QColor(255, 255, 0, 100))  # Sarı
                elif severity == "low":
                    vuln_item.setBackground(3, QColor(0, 255, 0, 100))  # Yeşil
                
                self.vuln_tab.addTopLevelItem(vuln_item)
        
        # Ağ haritasını güncelle
        self.network_graph.update_graph(results)
        
        # Durum çubuğunu güncelle
        total_vulns = sum(len(host_data.get("vulnerabilities", [])) for host_data in results.values())
        status_msg = f"{self.lang.get_text('main.scan_completed')} - "
        status_msg += f"{len(results)} host(s), {self.ports_tab.rowCount()} açık port, {total_vulns} güvenlik açığı bulundu"
        self.statusBar().showMessage(status_msg)
    
    def save_scan_results(self):
        """Tarama sonuçlarını dosyaya kaydet"""
        if not self.scan_history:
            QMessageBox.warning(self, self.lang.get_text("messages.warning"),
                              self.lang.get_text("messages.no_results"))
            return
        
        # En son tarama sonucunu al
        result = self.scan_history[-1]
        
        # Dosya adı seç
        file_path, _ = QFileDialog.getSaveFileName(
            self, self.lang.get_text("menu.save_results"), "", 
            "JSON Dosyaları (*.json);;Tüm Dosyalar (*)"
        )
        
        if not file_path:
            return
        
        # Sonuçları JSON formatında kaydet
        try:
            with open(file_path, 'w') as f:
                json.dump(result, f, indent=4)
            
            self.statusBar().showMessage(f"{self.lang.get_text('messages.save_success')}: {file_path}")
        except Exception as e:
            QMessageBox.critical(self, self.lang.get_text("messages.error"),
                               f"{self.lang.get_text('messages.save_error')}: {str(e)}")

    def change_language(self):
        """Change application language and refresh UI"""
        action = self.sender()
        if action:
            lang_code = action.data()
            if self.lang.set_language(lang_code):
                self.refresh_ui()
                # Save language preference
                settings = {
                    "language": lang_code,
                    "theme": "dark",  # Default theme
                    "thread_count": 10,
                    "timeout": 5
                }
                # TODO: Implement settings save functionality

    def refresh_ui(self):
        """Refresh all UI elements with new language."""
        # Window title and menu
        self.setWindowTitle(self.lang.get_text("app_title"))
        
        # Update menu items
        for menu in self.menuBar().findChildren(QMenu):
            menu_name = menu.objectName()
            if menu_name in ["file_menu", "edit_menu", "help_menu"]:
                menu.setTitle(self.lang.get_text(f"menu.{menu_name.split('_')[0]}"))
                
        # Update top panel
        self.target_input.setPlaceholderText(self.lang.get_text("main.target_placeholder"))
        self.scan_button.setText(self.lang.get_text("main.scan"))
        self.stop_button.setText(self.lang.get_text("main.stop"))
        
        # Update profile group
        profile_group = self.findChild(QGroupBox, "profile_group")
        if profile_group:
            profile_group.setTitle(self.lang.get_text("main.profile"))
            
        # Update command group
        command_group = self.findChild(QGroupBox, "command_group")
        if command_group:
            command_group.setTitle(self.lang.get_text("main.command"))
            
        # Update tab names
        self.result_tabs.setTabText(0, self.lang.get_text("tabs.nmap_output"))
        self.result_tabs.setTabText(1, self.lang.get_text("tabs.ports_hosts"))
        self.result_tabs.setTabText(2, self.lang.get_text("tabs.details"))
        self.result_tabs.setTabText(3, self.lang.get_text("tabs.topology"))
        self.result_tabs.setTabText(4, self.lang.get_text("tabs.vulnerabilities"))
        
        # Update status bar
        self.statusBar().showMessage(self.lang.get_text("main.ready"))
        
        # Force layout update
        self.update()
        self.repaint()

    def resizeEvent(self, event):
        """Pencere yeniden boyutlandırma olayını yönet"""
        super().resizeEvent(event)
        
        # Ana widget'ları bul
        content_splitter = self.findChild(QSplitter)
        if content_splitter:
            # Pencere genişliğine göre oransal boyutlandırma
            total_width = self.width()
            left_width = int(total_width * 0.2)  # Sol panel için %20
            center_width = int(total_width * 0.6)  # Orta panel için %60
            right_width = total_width - left_width - center_width  # Sağ panel için kalan
            content_splitter.setSizes([left_width, center_width, right_width])
        
        # İlerleme çubuğunu güncelle
        self.progress_bar.setFixedWidth(self.width() - 20)
        
        # Tablo sütunlarını güncelle
        header = self.ports_tab.horizontalHeader()
        total_width = self.ports_tab.width()
        header.setMinimumSectionSize(50)
        header.setSectionResizeMode(0, QHeaderView.Fixed)  # Port
        header.setSectionResizeMode(1, QHeaderView.Fixed)  # Protokol
        header.setSectionResizeMode(2, QHeaderView.Fixed)  # Durum
        header.setSectionResizeMode(3, QHeaderView.Stretch)  # Servis
        header.setSectionResizeMode(4, QHeaderView.Stretch)  # Sürüm
        header.resizeSection(0, 80)  # Port genişliği
        header.resizeSection(1, 80)  # Protokol genişliği
        header.resizeSection(2, 80)  # Durum genişliği
        
        # Güvenlik açıkları sekmesini güncelle
        vuln_header = self.vuln_tab.header()
        vuln_header.setMinimumSectionSize(50)
        vuln_header.setSectionResizeMode(0, QHeaderView.Fixed)  # Port
        vuln_header.setSectionResizeMode(1, QHeaderView.Fixed)  # Servis
        vuln_header.setSectionResizeMode(2, QHeaderView.Fixed)  # CVE ID
        vuln_header.setSectionResizeMode(3, QHeaderView.Fixed)  # Önem
        vuln_header.setSectionResizeMode(4, QHeaderView.Stretch)  # Açıklama
        vuln_header.resizeSection(0, 80)  # Port genişliği
        vuln_header.resizeSection(1, 100)  # Servis genişliği
        vuln_header.resizeSection(2, 120)  # CVE ID genişliği
        vuln_header.resizeSection(3, 80)  # Önem genişliği
        
        # Host ağacını güncelle
        self.hosts_tree.setColumnWidth(0, self.hosts_tree.width() - 20)
        
        # Tüm sekmelerin içeriğini güncelle
        for i in range(self.result_tabs.count()):
            widget = self.result_tabs.widget(i)
            if isinstance(widget, QTextEdit):
                widget.setMinimumWidth(center_width - 40)
        
        # Hemen güncelle
        self.update()

    def sizeHint(self):
        """Önerilen pencere boyutunu belirle"""
        return QSize(1200, 800)

    def minimumSizeHint(self):
        """Minimum pencere boyutunu belirle"""
        return QSize(800, 600)

    def scan_error(self, error_message):
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        QMessageBox.critical(self, self.lang.get_text("messages.error"), error_message)
        self.statusBar().showMessage(self.lang.get_text("main.ready"))


def main():
    """Ana uygulama fonksiyonu"""
    app = QApplication(sys.argv)
    window = ReanzapMainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main() 