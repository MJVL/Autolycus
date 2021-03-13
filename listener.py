import pyshark
import argparse
import sys
import logging


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("interface", help="The interface to listen on.", type=str)
    args = parser.parse_args()

    # pyshark makes heavy use of futures, which carry a plethora of errors when quitting
    # since we're running this in an "infinite loop", let's allow gross exits without printing the errors
    sys.stderr = object

    active_connections = set()

    try:
        capture = pyshark.LiveCapture(interface=args.interface, bpf_filter="tcp")
        for packet in capture.sniff_continuously():
            if "Synergy" in packet:
                # handshake data
                if "handshake" in packet.synergy.field_names:
                    active_connections.add(packet.ip.src)
                    print(f"[HANDSHAKE] {packet.ip.src} is establishing a connection with {packet.ip.dst}")
                    print(f"\tVersion: Synergy v{packet.synergy.handshake_majorversion}.{packet.synergy.handshake_minorversion}")
                    if (set([packet.ip.src, packet.ip.dst]).issubset(active_connections)):
                        print(f"[HANDSHAKE] Connection established between {packet.ip.dst} <-> {packet.ip.src}")
                        print(f"\tServer: {packet.ip.dst}")
                        print(f"\tClient: {packet.ip.src}, hostname: {packet.synergy.handshake_client}")
                    continue
    
                # post-handshake setup data
                if "qinf" in packet.synergy.field_names:
                    print(f"[SETUP] {packet.ip.src} is sending server screen settings")
                if "clientdata" in packet.synergy.field_names:
                    print(f"[SETUP] {packet.ip.src} is confirming server screen settings")
                    for field in packet.synergy._get_all_fields_with_alternates()[1:]:
                        print(f"\t{packet.synergy._get_field_repr(field)}")

                # ignore noisy packets (mouse movements, NOPs, keep alives, and unknowns)
                if len(packet.synergy.field_names) > 0 and not any(field in ("mousemoved", "cnop", "calv", "unknown") for field in packet.synergy.field_names):
                    pass
                    packet.synergy.pretty_print()

    except (EOFError, KeyboardInterrupt):
        print("\nExiting...")


if __name__ == "__main__":
    main()
