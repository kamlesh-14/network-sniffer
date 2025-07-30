# Network Packet Sniffer with GUI, Port Scan & Ping Detection

## 🔢 Description
A Python-based GUI application using **Scapy** and **Tkinter** to:
- Capture live packets
- Display Source IP, Destination IP, and Protocol
- Detect **port scanning**, **ping sweeps**
- Alert with **sound** on suspicious activity
- Allow **pause/resume** of sniffing

---

## 📂 Project Structure
```
network-sniffer/
│
├── sniffer.py         # Main GUI + Scapy logic
├── README.md
```

---

## 🔐 Requirements
- Python 3.x
- scapy
- tkinter (built-in)
- playsound

```bash
pip install scapy playsound
```

---

## 🚀 Run the Program
```bash
python sniffer.py
```

---

## 🔢 Detection Logic
### Ping Detection:
- Any **ICMP** echo request packet triggers alert

### Port Scan Detection:
- Multiple TCP/UDP packets from same source to **many ports** in short time
- Alert is triggered when same source IP targets multiple unique ports quickly

---

## 🌟 Author
Created by **Kamlesh** for learning & demonstrating real-time packet inspection and anomaly detection.
