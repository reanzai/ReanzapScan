from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                           QSpinBox, QComboBox, QPushButton, QTabWidget,
                           QWidget, QFormLayout)
from PyQt5.QtCore import Qt

class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.lang = parent.lang if parent else None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle(self.lang.get_text("settings.title"))
        self.setMinimumWidth(400)

        layout = QVBoxLayout()
        self.setLayout(layout)

        # Create tab widget
        tab_widget = QTabWidget()
        layout.addWidget(tab_widget)

        # General settings tab
        general_tab = QWidget()
        general_layout = QFormLayout()
        general_tab.setLayout(general_layout)

        # Language selection
        self.language_combo = QComboBox()
        for code, name in self.lang.get_available_languages().items():
            self.language_combo.addItem(name, code)
        current_index = self.language_combo.findData(self.lang.get_current_language())
        if current_index >= 0:
            self.language_combo.setCurrentIndex(current_index)
        general_layout.addRow(self.lang.get_text("settings.language"), self.language_combo)

        # Theme selection
        self.theme_combo = QComboBox()
        self.theme_combo.addItem(self.lang.get_text("settings.light"))
        self.theme_combo.addItem(self.lang.get_text("settings.dark"))
        general_layout.addRow(self.lang.get_text("settings.theme"), self.theme_combo)

        tab_widget.addTab(general_tab, self.lang.get_text("settings.general"))

        # Scanning settings tab
        scanning_tab = QWidget()
        scanning_layout = QFormLayout()
        scanning_tab.setLayout(scanning_layout)

        # Thread count
        self.thread_count = QSpinBox()
        self.thread_count.setRange(1, 100)
        self.thread_count.setValue(10)
        scanning_layout.addRow(self.lang.get_text("settings.thread_count"), self.thread_count)

        # Timeout
        self.timeout = QSpinBox()
        self.timeout.setRange(1, 60)
        self.timeout.setValue(5)
        scanning_layout.addRow(self.lang.get_text("settings.timeout"), self.timeout)

        tab_widget.addTab(scanning_tab, self.lang.get_text("settings.scanning"))

        # Buttons
        button_layout = QHBoxLayout()
        layout.addLayout(button_layout)

        save_button = QPushButton(self.lang.get_text("settings.save"))
        save_button.clicked.connect(self.accept)
        button_layout.addWidget(save_button)

        cancel_button = QPushButton(self.lang.get_text("settings.cancel"))
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)

    def get_settings(self):
        return {
            "language": self.language_combo.currentData(),
            "theme": "dark" if self.theme_combo.currentIndex() == 1 else "light",
            "thread_count": self.thread_count.value(),
            "timeout": self.timeout.value()
        }

    def set_settings(self, settings):
        if "language" in settings:
            index = self.language_combo.findData(settings["language"])
            if index >= 0:
                self.language_combo.setCurrentIndex(index)

        if "theme" in settings:
            self.theme_combo.setCurrentIndex(1 if settings["theme"] == "dark" else 0)

        if "thread_count" in settings:
            self.thread_count.setValue(settings["thread_count"])

        if "timeout" in settings:
            self.timeout.setValue(settings["timeout"]) 