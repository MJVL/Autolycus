import pyshark
import argparse


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("interface", help="The interface to listen on.", type=str)
    args = parser.parse_args()

    try:
        capture = pyshark.LiveCapture(interface=args.interface, bpf_filter="tcp")
        for packet in capture.sniff_continuously(packet_count=1):
            print(packet.ip)
            print(packet.data)
    except Exception:
        print("Exiting...")


if __name__ == "__main__":
    main()