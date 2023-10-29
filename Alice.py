import socket
import sys

from data_classes import Header, Segment

HOST_IP = "127.0.0.1"
MAX_PAYLOAD_BYTES = 64  # Inclusive of headers
TIMEOUT_MS = 50
MAX_INPUT_BYTES = 5000


def main() -> None:
    unreli_net_address = (HOST_IP, get_unreli_net_port())
    segments = segment_data(read_data())

    # Connect to UnreliNET via UDP.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(TIMEOUT_MS / 1000)

        for segment in segments:
            sequence_num = segment.header.sequence_num

            while True:
                s.sendto(segment.encode(), unreli_net_address)
                try:
                    data, _ = s.recvfrom(MAX_PAYLOAD_BYTES)
                    ack = Segment.decode(data)
                    if ack.has_no_bit_error() and ack.header.ack_num == sequence_num:
                        break
                except socket.timeout:
                    pass


def get_unreli_net_port() -> int:
    return int(sys.argv[1])


def read_data() -> bytes:
    return sys.stdin.buffer.read(MAX_INPUT_BYTES)


def segment_data(data: bytes) -> list[Segment]:
    chunk_size = MAX_PAYLOAD_BYTES - Header.HEADER_SIZE_BYTES

    # Split data into chunks.
    data_chunks: list[bytes] = []
    for i in range(0, len(data), chunk_size):
        data_chunks.append(data[i : i + chunk_size])

    return [
        Segment.create_data_segment(
            sequence_num=i % 2,
            data=data,
        )
        for i, data in enumerate(data_chunks)
    ]


if __name__ == "__main__":
    main()
