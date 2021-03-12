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

    try:
        capture = pyshark.LiveCapture(interface=args.interface, bpf_filter="tcp")
        for packet in capture.sniff_continuously():
            if "Synergy" in packet:
                # ignore noisy packets (mouse movements, NOPs, and keep alives)
                if len(packet.synergy.field_names) > 0 and not any(field in ("mousemoved", "cnop", "calv") for field in packet.synergy.field_names):
                    packet.synergy.pretty_print()
    except (EOFError, KeyboardInterrupt):
        print("\nExiting...")


if __name__ == "__main__":
    main()