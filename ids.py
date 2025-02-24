"""
IDS will comprise of four main components:
    1) A packet capture system
    2) Traffic analysis module
    3) A detection engine
    4) An alert system
"""

from scapy.all import sniff, TCP, IP
from collections import defaultdict
import threading
import queue

class PacketCapture:
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.stop_capture = threading.Event()

    def packet_callback(self,packet):
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)
    
    def start_capture(self, interface="eth0"):
        def capture_thread():
            sniff(iface=interface,
            prn = self.packet_callback,
            store = 0,
            stop_filter=lambda _: self.stop_capture.is_set())

        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()
    
    def stop(self):
        self.stop_capture.set()
        self.capture_thread.join()
