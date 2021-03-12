import pyshark
import argparse
import sys


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
                if "handshake" in packet.synergy.field_names:
                    active_connections.add(packet.ip.src)
                    print(f"{packet.ip.src} (Synergy v{packet.synergy.handshake_majorversion}.{packet.synergy.handshake_minorversion}) is establishing a connection with {packet.ip.dst}")
                    if packet.ip.src in active_connections and packet.ip.dst in active_connections:
                        print(f"Connection established between {packet.ip.dst} <-> {packet.ip.src}")
                        print(f"Client ({packet.ip.src}) has hostname ({packet.synergy.handshake_client})")
                    continue
    
                # ignore noisy packets (mouse movements, NOPs, keep alives, and unknowns)
                if len(packet.synergy.field_names) > 0 and not any(field in ("mousemoved", "cnop", "calv", "unknown") for field in packet.synergy.field_names):
                    packet.synergy.pretty_print()
                    
    except (EOFError, KeyboardInterrupt):
        print("\nExiting...")


if __name__ == "__main__":
    main()