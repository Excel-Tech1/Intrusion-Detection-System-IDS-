import scapy.all as scapy
from scapy.layers.inet import IP, TCP
from tkinter import Tk, Text, Button, Scrollbar, Label, END, DISABLED, NORMAL
import threading
import csv
import time


class IDSRules:
    def __init__(self, description, protocol, dst_port=None, keywords=None):
        self.description = description
        self.protocol = protocol
        self.dst_port = dst_port
        self.keywords = keywords or []

    def match(self, packet):
        if IP in packet and packet.haslayer(self.protocol):
            proto_layer = packet[self.protocol]

            if self.dst_port and proto_layer.dport != self.dst_port:
                return False

            # Check payload for SQL keywords
            if self.keywords and packet.haslayer(scapy.Raw):
                payload = packet[scapy.Raw].load.decode(errors="ignore").lower()
                for keyword in self.keywords:
                    if keyword.lower() in payload:
                        return True
                return False

            return True
        return False


class IDS:
    def __init__(self, interface, gui):
        self.interface = interface
        self.gui = gui
        self.rules = []
        self.running = False
        self.txt_file = "ids_output.txt"
        self.csv_file = "ids_output.csv"

    def add_rule(self, rule):
        self.rules.append(rule)

    def start_sniffing(self):
        self.running = True
        scapy.sniff(iface=self.interface, prn=self.process_packet, store=False, stop_filter=lambda x: not self.running)

    def stop_sniffing(self):
        self.running = False

    def process_packet(self, packet):
        if not packet.haslayer(IP):
            return

        for rule in self.rules:
            if rule.match(packet):
                msg = f"[ALERT] {rule.description} | {packet[IP].src} → {packet[IP].dst} | {time.ctime(packet.time)}"
                self.gui.log_alert(msg)
                self.write_to_txt(msg)
                self.write_to_csv(rule.description, packet[IP].src, packet[IP].dst, packet.time)

    def write_to_txt(self, message):
        with open(self.txt_file, "a") as f:
            f.write(message + "\n")

    def write_to_csv(self, description, src_ip, dst_ip, timestamp):
        with open(self.csv_file, "a", newline="") as f:
            writer = csv.writer(f)
            if f.tell() == 0:
                writer.writerow(["Description", "Source IP", "Destination IP", "Timestamp"])
            writer.writerow([description, src_ip, dst_ip, timestamp])


class IDS_GUI:
    def __init__(self, master):
        self.master = master
        master.title("IDS - GUI")
        master.geometry("700x400")

        self.label = Label(master, text="Intrusion Detection System (GUI)", font=("Helvetica", 14, "bold"))
        self.label.pack()

        self.text_area = Text(master, height=18, state=DISABLED, wrap='word')
        self.text_area.pack(padx=10, pady=10, fill="both", expand=True)

        self.scrollbar = Scrollbar(master, command=self.text_area.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.text_area.config(yscrollcommand=self.scrollbar.set)

        self.start_button = Button(master, text="Start IDS", command=self.start_ids, bg="green", fg="white")
        self.start_button.pack(side="left", padx=10)

        self.stop_button = Button(master, text="Stop IDS", command=self.stop_ids, bg="red", fg="white", state=DISABLED)
        self.stop_button.pack(side="right", padx=10)

        self.ids = IDS("wlp4s0", self)  # update interface if needed
        self.setup_rules()
        self.sniff_thread = None

    def setup_rules(self):
        ssh_rule = IDSRules("SSH Brute-force attempt", TCP, dst_port=22)
        sql_keywords = ["select", "union", "' or 1=1", "drop", "insert", "--"]
        sql_rule = IDSRules("SQL Injection Attempt", TCP, dst_port=80, keywords=sql_keywords)
        self.ids.add_rule(ssh_rule)
        self.ids.add_rule(sql_rule)

    def log_alert(self, message):
        self.text_area.config(state=NORMAL)
        self.text_area.insert(END, message + "\n")
        self.text_area.see(END)
        self.text_area.config(state=DISABLED)

    def start_ids(self):
        self.log_alert("[INFO] Starting packet sniffing...")
        self.start_button.config(state=DISABLED)
        self.stop_button.config(state=NORMAL)
        self.sniff_thread = threading.Thread(target=self.ids.start_sniffing)
        self.sniff_thread.start()

    def stop_ids(self):
        self.log_alert("[INFO] Stopping packet sniffing...")
        self.ids.stop_sniffing()
        self.start_button.config(state=NORMAL)
        self.stop_button.config(state=DISABLED)


if __name__ == "__main__":
    root = Tk()
    app = IDS_GUI(root)
    root.mainloop()
