#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Reanzap - Ağ Görselleştirme Modülü
"""

import matplotlib.pyplot as plt
import networkx as nx
from PyQt5.QtWidgets import QWidget, QVBoxLayout
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure


class NetworkGraph(QWidget):
    """Ağ grafiği görselleştirme widget'ı"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        
    def init_ui(self):
        """UI bileşenlerini oluştur"""
        layout = QVBoxLayout(self)
        
        # Matplotlib figürü ve canvas'ı oluştur
        self.figure = Figure(figsize=(8, 6), dpi=100)
        self.canvas = FigureCanvas(self.figure)
        layout.addWidget(self.canvas)
        
        # Boş bir ağ grafiği oluştur
        self.graph = nx.Graph()
        self.ax = self.figure.add_subplot(111)
    
    def clear_graph(self):
        """Grafiği temizle"""
        self.graph.clear()
        self.ax.clear()
        self.canvas.draw()
    
    def update_graph(self, scan_data):
        """Tarama verilerine göre grafiği güncelle"""
        self.clear_graph()
        
        if not scan_data:
            return
        
        # Tarama verilerinden host ve port bilgilerini çıkar
        hosts = scan_data.get("results", [])
        scan_details = scan_data.get("scan_data", {})
        
        if not hosts:
            return
        
        # Ana ağ düğümünü ekle (merkez)
        network_node = "Ağ"
        self.graph.add_node(network_node, type="network")
        
        # Her host için düğüm ekle
        for host in hosts:
            host_data = scan_details.get(host, {})
            status = host_data.get("status", {}).get("state", "")
            
            # Sadece aktif hostları ekle
            if status == "up":
                self.graph.add_node(host, type="host")
                self.graph.add_edge(network_node, host)
                
                # Açık portları ekle
                tcp_ports = host_data.get("tcp", {})
                for port, port_data in tcp_ports.items():
                    if port_data.get("state") == "open":
                        port_name = f"{port}/{port_data.get('name', 'unknown')}"
                        port_node = f"{host}:{port_name}"
                        self.graph.add_node(port_node, type="port")
                        self.graph.add_edge(host, port_node)
        
        # Grafiği çiz
        self.draw_graph()
    
    def draw_graph(self):
        """Grafiği çiz"""
        self.ax.clear()
        
        # Düğüm pozisyonlarını hesapla
        pos = nx.spring_layout(self.graph)
        
        # Düğüm türlerine göre renkleri belirle
        node_colors = []
        node_sizes = []
        
        for node in self.graph.nodes():
            node_type = self.graph.nodes[node].get("type", "")
            
            if node_type == "network":
                node_colors.append("red")
                node_sizes.append(1000)
            elif node_type == "host":
                node_colors.append("blue")
                node_sizes.append(700)
            elif node_type == "port":
                node_colors.append("green")
                node_sizes.append(400)
            else:
                node_colors.append("gray")
                node_sizes.append(300)
        
        # Düğümleri çiz
        nx.draw_networkx_nodes(
            self.graph, pos,
            node_color=node_colors,
            node_size=node_sizes,
            alpha=0.8,
            ax=self.ax
        )
        
        # Kenarları çiz
        nx.draw_networkx_edges(
            self.graph, pos,
            width=1.0,
            alpha=0.5,
            ax=self.ax
        )
        
        # Etiketleri çiz
        nx.draw_networkx_labels(
            self.graph, pos,
            font_size=8,
            font_family="sans-serif",
            ax=self.ax
        )
        
        # Grafiği düzenle
        self.ax.set_title("Ağ Haritası")
        self.ax.axis("off")
        
        # Canvas'ı güncelle
        self.canvas.draw() 