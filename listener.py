import pyshark
import argparse
import sys
import logging
from fabulous import text
from colorlog import ColoredFormatter


# custom logging levels
HDSHK = 5
SETUP = 6
DATA = 7

# other constants
BANNER_WIDTH = 115


def setup_logger():
    logging.addLevelName(HDSHK, "HDSHK")
    logging.addLevelName(SETUP, "SETUP")
    logging.addLevelName(DATA, "DATA")
    formatter = ColoredFormatter(
        "%(asctime)s | %(log_color)s%(levelname)-5s%(reset)s | %(log_color)s%(reset)s%(message)s",
        datefmt="%H:%M:%S",
        reset=True,
        log_colors={
            'INFO': 'green',
            'HDSHK': 'green',
            'SETUP': 'green',
            'DATA': 'green'
        }
    )

    logger = logging.getLogger('example')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel("HDSHK")

    return logger


def print_banner():
    print("*" * BANNER_WIDTH)
    print(text.Text("Autolycus", color="#EF9C70", shadow=True, skew=3))
    print("*" * BANNER_WIDTH)
    print("Author: Michael Van Leeuwen".center(BANNER_WIDTH, ' '))
    print("github.com/MJVL/Autolycus".center(BANNER_WIDTH, ' '))
    print("*" * BANNER_WIDTH)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("interface", help="The interface to listen on.", type=str)
    args = parser.parse_args()

    log = setup_logger()

    # pyshark makes heavy use of futures, which carry a plethora of errors when quitting
    # since we're running this in an "infinite loop", let's allow gross exits without printing the errors
    sys.stderr = object

    print_banner()


    active_connections = set()
    try:
        log.info("Listening for events...")
        capture = pyshark.LiveCapture(interface=args.interface, bpf_filter="tcp")
        for packet in capture.sniff_continuously():

            if "Synergy" in packet:
                # handshake data
                if "handshake" in packet.synergy.field_names:
                    active_connections.add(packet.ip.src)
                    log.log(HDSHK, f"{packet.ip.src} is establishing a connection with {packet.ip.dst}")
                    log.log(HDSHK, f"\tVersion: Synergy v{packet.synergy.handshake_majorversion}.{packet.synergy.handshake_minorversion}")
                    if (set([packet.ip.src, packet.ip.dst]).issubset(active_connections)):
                        log.log(HDSHK, f"Connection established between {packet.ip.dst} <-> {packet.ip.src}")
                        log.log(HDSHK, f"\tServer: {packet.ip.dst}")
                        log.log(HDSHK, f"\tClient: {packet.ip.src}, hostname: {packet.synergy.handshake_client}")
                    continue
    
                # post-handshake setup data
                if "qinf" in packet.synergy.field_names:
                    log.log(SETUP, f"{packet.ip.src} is sending server screen settings")
                if "clientdata" in packet.synergy.field_names:
                    log.log(SETUP, f"{packet.ip.src} is confirming server screen settings")
                    for field in packet.synergy._get_all_fields_with_alternates()[1:]:
                        log.log(SETUP, f"\t{packet.synergy._get_field_repr(field)}")

                # ignore noisy packets (mouse movements, NOPs, keep alives, and unknowns)
                if len(packet.synergy.field_names) > 0 and not any(field in ("mousemoved", "cnop", "calv", "unknown") for field in packet.synergy.field_names):
                    pass
                    #packet.synergy.pretty_print()
                    #print(packet.synergy.field_names)

    except (EOFError, KeyboardInterrupt):
        print("\nExiting...")


if __name__ == "__main__":
    main()
