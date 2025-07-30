import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP
import tkinter as tk
from datetime import datetime, timedelta
from collections import defaultdict

# Track connections for port scan detection
connection_tracker = defaultdict(list)

# Sniffing control
sniffing = False
paused = False

# Thresholds
PORT_SCAN_THRESHOLD = 10
PORT_SCAN_WINDOW = timedelta(seconds=5)

def analyze_packet(packet, text_widget):
    global paused
    if paused:
        return

    alert = False
    display_text = ""

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if TCP in packet:
            dst_port = packet[TCP].dport
            connection_tracker[src_ip].append((datetime.now(), dst_port))
            connection_tracker[src_ip] = [
                (t, p) for t, p in connection_tracker[src_ip] if datetime.now() - t <= PORT_SCAN_WINDOW
            ]
            unique_ports = set(p for t, p in connection_tracker[src_ip])
            if len(unique_ports) >= PORT_SCAN_THRESHOLD:
                alert = True
                display_text = f"[!] Port Scan Detected: {src_ip} -> {dst_ip} (ports: {sorted(unique_ports)})\n"
            else:
                display_text = f"[+] TCP Packet: {src_ip}:{packet[TCP].sport} -> {dst_ip}:{dst_port}\n"

        elif UDP in packet:
            display_text = f"[+] UDP Packet: {src_ip}:{packet[UDP].sport} -> {dst_ip}:{packet[UDP].dport}\n"

        elif ICMP in packet:
            if hasattr(packet[ICMP], 'type') and packet[ICMP].type == 8:
                alert = True
                display_text = f"[!] ICMP Ping Detected: {src_ip} -> {dst_ip}\n"
            else:
                display_text = f"[+] ICMP Packet: {src_ip} -> {dst_ip}\n"

        else:
            display_text = f"[+] Other Packet: {src_ip} -> {dst_ip}\n"

        # Display in GUI
        if alert:
            text_widget.insert(tk.END, display_text, 'alert')
        else:
            text_widget.insert(tk.END, display_text)
        text_widget.see(tk.END)

def start_sniffing(text_widget):
    sniff(prn=lambda pkt: analyze_packet(pkt, text_widget), store=False)

def toggle_sniffing(text_widget, start_btn, pause_btn):
    global sniffing
    if not sniffing:
        sniffing = True
        start_btn.config(state=tk.DISABLED)
        pause_btn.config(state=tk.NORMAL)
        threading.Thread(target=start_sniffing, args=(text_widget,), daemon=True).start()

def toggle_pause(pause_btn):
    global paused
    paused = not paused
    pause_btn.config(text="Resume Sniffing" if paused else "Pause Sniffing")

def create_gui():
    root = tk.Tk()
    root.title("Network Packet Sniffer")

    text = tk.Text(root, bg="black", fg="white", wrap="word")
    text.pack(fill=tk.BOTH, expand=True)

    text.tag_config('alert', foreground='red')

    button_frame = tk.Frame(root)
    button_frame.pack(pady=10)

    start_btn = tk.Button(button_frame, text="Start Sniffing", command=lambda: toggle_sniffing(text, start_btn, pause_btn))
    start_btn.pack(side=tk.LEFT, padx=5)

    pause_btn = tk.Button(button_frame, text="Pause Sniffing", state=tk.DISABLED, command=lambda: toggle_pause(pause_btn))
    pause_btn.pack(side=tk.LEFT, padx=5)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
