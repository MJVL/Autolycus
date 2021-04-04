import pyshark
import argparse
import sys
import logging
from fabulous import text
from colorlog import ColoredFormatter


class Autolycus(object):
    __slots__ = ["interface", "capture", "log", "active_connections"]

    # packet type constants
    PACKET = {
        "HANDSHAKE": "handshake",
        "QUERY_INFO": "qinf",
        "CLIENT_DATA": "client_data",
        "ACK": "ack", 
        "KEEP_ALIVE": "calv",
        "MOUSE_MOVEMENT": "mousemoved",
        "NO_OPERATION": "cnop",
        "UNKNOWN": "unknown"
    }

    # logging constants
    HDSHK = 5
    SETUP = 6
    DATA = 7
    CONN = 8

    def __init__(self, interface):
        self.interface = interface
        self.capture = capture = pyshark.LiveCapture(interface=interface, bpf_filter="tcp")
        self.log = self.setup_logger()
        self.active_connections = set()

    def start(self):
        self.print_banner()
        self.log.info("Listening for events...")
        self.listen_loop()

    def listen_loop(self):
        for packet in self.capture.sniff_continuously():
            if "Synergy" in packet and len(packet.synergy.field_names) > 0:
                packet_type = packet.synergy.field_names[0]

                if packet.ip.src not in self.active_connections and packet.ip.dst not in self.active_connections:
                    self.active_connections.add(packet.ip.src)
                    self.active_connections.add(packet.ip.dst)
                    self.log.log(self.CONN, f"Discovered ongoing session between {packet.ip.dst} <-> {packet.ip.src}")

                if packet_type == self.PACKET["HANDSHAKE"]:
                    self.handle_handshake(packet)
                elif packet_type == self.PACKET["QUERY_INFO"]:
                    self.handle_query_info(packet)
                elif packet_type == self.PACKET["CLIENT_DATA"]:
                    self.handle_client_data(packet)
                elif packet_type == self.PACKET["ACK"]:
                    self.handle_ack(packet)
                elif packet_type == self.PACKET["KEEP_ALIVE"]:
                    pass
                elif packet_type == self.PACKET["NO_OPERATION"]:
                    pass
                elif packet_type == self.PACKET["UNKNOWN"]:
                    pass
                elif packet_type == self.PACKET["MOUSE_MOVEMENT"]:
                    pass
                elif len(packet.synergy.field_names) > 0:
                    packet.synergy.pretty_print()
                    print(packet.synergy.field_names)
    
    def handle_handshake(self, packet):
        self.active_connections.add(packet.ip.src)
        self.log.log(self.HDSHK, f"{packet.ip.src} is establishing a connection with {packet.ip.dst}")
        self.log.log(self.HDSHK, f"\tVersion: Synergy v{packet.synergy.handshake_majorversion}.{packet.synergy.handshake_minorversion}")
        if (set([packet.ip.src, packet.ip.dst]).issubset(self.active_connections)):
            self.log.log(self.HDSHK, f"Connection established between {packet.ip.dst} <-> {packet.ip.src}")
            self.log.log(self.HDSHK, f"\tServer: {packet.ip.dst}")
            self.log.log(self.HDSHK, f"\tClient: {packet.ip.src}, hostname: {packet.synergy.handshake_client}")

    def handle_query_info(self, packet):
        self.log.log(self.SETUP, f"{packet.ip.src} is requesting screen settings")

    def handle_ack(self, packet):
        self.log.log(self.SETUP, f"{packet.ip.src} has acknowledged the sent settings")

    def handle_client_data(self, packet):
        self.log.log(self.SETUP, f"{packet.ip.src} is confirming server screen settings")
        for field in packet.synergy._get_all_fields_with_alternates()[1:]:
            self.log.log(self.SETUP, f"\t{packet.synergy._get_field_repr(field)}")

    def print_banner(self):
        BANNER_WIDTH = 115
        print("*" * BANNER_WIDTH)
        print(text.Text("Autolycus", color="#EF9C70", shadow=True, skew=3))
        print("*" * BANNER_WIDTH)
        print("Author: Michael Van Leeuwen".center(BANNER_WIDTH, ' '))
        print("github.com/MJVL/Autolycus".center(BANNER_WIDTH, ' '))
        print("*" * BANNER_WIDTH)

    def setup_logger(self):
        logging.addLevelName(self.HDSHK, "HDSHK")
        logging.addLevelName(self.SETUP, "SETUP")
        logging.addLevelName(self.DATA, "DATA")
        logging.addLevelName(self.CONN, "CONN")
        formatter = ColoredFormatter(
            "%(asctime)s | %(log_color)s%(levelname)-5s%(reset)s | %(log_color)s%(reset)s%(message)s",
            datefmt="%H:%M:%S",
            reset=True,
            log_colors={
                'INFO': 'green',
                'HDSHK': 'green',
                'SETUP': 'green',
                'DATA': 'green',
                'CONN': 'green'
            }
        )
        logger = logging.getLogger('example')
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel("HDSHK")
        #sys.stderr = object
        return logger


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("interface", help="The interface to listen on.", type=str)
    args = parser.parse_args()

    autolycus = Autolycus(args.interface)
    autolycus.start()

if __name__ == "__main__":
    main()
