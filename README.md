# ReanzapScan - Advanced Network Scanner / Gelişmiş Ağ Tarayıcı

[English](#english) | [Türkçe](#türkçe)

## English

### Description
Reanzap is an advanced network scanning tool with a modern graphical interface. It provides comprehensive network analysis capabilities including port scanning, service detection, vulnerability assessment, and network topology visualization.

### Features
- Fast and efficient port scanning
- Service and version detection
- Vulnerability scanning with CVE database integration
- Network topology visualization
- Operating system detection
- Beautiful and modern GUI
- Multi-language support (English/Turkish)
- Detailed scan reports
- JSON export capability

### Requirements
- Python 3.8 or higher
- PyQt5
- Scapy
- Requests
- Networkx
- Matplotlib
- Psutil
- Colorama

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/ReanzapScan.git
cd ReanzapScan
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Additional requirements:
- **Windows**: Install Npcap from [https://npcap.com/](https://npcap.com/)
- **Linux**: Install libpcap
  ```bash
  # Debian/Ubuntu
  sudo apt-get install libpcap-dev
  # Fedora
  sudo dnf install libpcap-devel
  # Arch Linux
  sudo pacman -S libpcap
  ```

### Usage
1. Run the application:
```bash
python reanzap.py
```

2. Enter target IP address or network range
3. Select scan profile
4. Click "Scan" button

### Security Note
Some scanning features require root/administrator privileges. On Linux, run with sudo:
```bash
sudo python reanzap.py
```

### License
This project is licensed under the MIT License - see the LICENSE file for details.

---

## Türkçe

### Açıklama
Reanzap, modern grafiksel arayüze sahip gelişmiş bir ağ tarama aracıdır. Port tarama, servis tespiti, güvenlik açığı değerlendirmesi ve ağ topolojisi görselleştirme gibi kapsamlı ağ analizi özellikleri sunar.

### Özellikler
- Hızlı ve verimli port tarama
- Servis ve sürüm tespiti
- CVE veritabanı entegrasyonlu güvenlik açığı taraması
- Ağ topolojisi görselleştirme
- İşletim sistemi tespiti
- Güzel ve modern arayüz
- Çoklu dil desteği (İngilizce/Türkçe)
- Detaylı tarama raporları
- JSON dışa aktarma özelliği

### Gereksinimler
- Python 3.8 veya üstü
- PyQt5
- Scapy
- Requests
- Networkx
- Matplotlib
- Psutil
- Colorama

### Kurulum

1. Depoyu klonlayın:
```bash
git clone https://github.com/yourusername/ReanzapScan.git
cd ReanzapScan
```

2. Bağımlılıkları yükleyin:
```bash
pip install -r requirements.txt
```

3. Ek gereksinimler:
- **Windows**: [https://npcap.com/](https://npcap.com/) adresinden Npcap'i yükleyin
- **Linux**: libpcap yükleyin
  ```bash
  # Debian/Ubuntu
  sudo apt-get install libpcap-dev
  # Fedora
  sudo dnf install libpcap-devel
  # Arch Linux
  sudo pacman -S libpcap
  ```

### Kullanım
1. Uygulamayı çalıştırın:
```bash
python reanzap.py
```

2. Hedef IP adresi veya ağ aralığını girin
3. Tarama profilini seçin
4. "Tara" butonuna tıklayın

### Güvenlik Notu
Bazı tarama özellikleri root/yönetici izinleri gerektirir. Linux'ta sudo ile çalıştırın:
```bash
sudo python reanzap.py
```

### Lisans
Bu proje MIT Lisansı altında lisanslanmıştır - detaylar için LICENSE dosyasına bakın. 