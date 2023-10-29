import socket
import sys
from typing import Literal

from data_classes import Segment

HOST_IP = "127.0.0.1"
MAX_PAYLOAD_BYTES = 64  # Inclusive of headers
TIMEOUT_MS = 50
MAX_INPUT_BYTES = 5000


def main() -> None:
    unreli_net_address = (HOST_IP, get_unreli_net_port())
    latest_received_sequence_num: Literal[0, 1] = 0

    # Connect to UnreliNET via UDP.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(unreli_net_address)

        data, _ = s.recvfrom(MAX_PAYLOAD_BYTES)
        segment = Segment.decode(data)

        if (
            segment.has_no_bit_error()
            and segment.header.sequence_num != latest_received_sequence_num
        ):
            print(segment.data.decode("ascii"))
            latest_received_sequence_num = segment.header.sequence_num  # type: ignore

        ack = Segment.create_ack(ack_num=segment.header.sequence_num)
        s.sendto(ack.encode(), unreli_net_address)


def get_unreli_net_port() -> int:
    return int(sys.argv[1])


if __name__ == "__main__":
    main()
