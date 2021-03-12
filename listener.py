import pyshark
import argparse


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("interface", help="The interface to listen on.", type=str)
    args = parser.parse_args()

    try:
        capture = pyshark.LiveCapture(interface=args.interface, bpf_filter="tcp")
        for packet in capture.sniff_continuously():
            if "Synergy" in packet:
                # ignore noisy packets (mouse movements, NOPs, keep alives, and unknowns)
                if len(packet.synergy.field_names) > 0 and not any(field in ("mousemoved", "cnop", "calv", "unknown") for field in packet.synergy.field_names):
                    packet.synergy.pretty_print()
    except (EOFError, KeyboardInterrupt):
        print("Exiting...")

if __name__ == "__main__":
    main()