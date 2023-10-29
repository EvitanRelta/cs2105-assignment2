import socket
import sys

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


def segment_data(data: bytes) -> list["Segment"]:
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


# ==============================================================================
#                Custom dataclasses (shared between Alice & Bob)
# ==============================================================================
import struct
import zlib
from dataclasses import dataclass
from typing import ClassVar


@dataclass
class Header:
    HEADER_SIZE_BYTES: ClassVar[int] = 12

    sequence_num: int
    is_ack: bool
    ack_num: int = 0
    checksum: int = 0

    def encode(self) -> bytes:
        return struct.pack(
            ">IIHH",
            self.sequence_num,
            self.ack_num,
            int(self.is_ack),
            self.checksum,
        )

    def with_checksum(self, checksum: int) -> "Header":
        return Header(
            sequence_num=self.sequence_num,
            is_ack=self.is_ack,
            ack_num=self.ack_num,
            checksum=checksum,
        )

    @staticmethod
    def decode(header: bytes) -> "Header":
        (
            sequence_num,
            ack_num,
            is_ack_int,
            checksum,
        ) = struct.unpack(">IIHH", header)
        return Header(
            sequence_num=sequence_num,
            is_ack=bool(is_ack_int),
            ack_num=ack_num,
            checksum=checksum,
        )


@dataclass
class Segment:
    header: Header
    data: bytes

    def encode(self) -> bytes:
        checksum = Segment._compute_checksum(self.header.encode() + self.data)
        return self.header.with_checksum(checksum).encode() + self.data

    def has_no_bit_error(self) -> bool:
        expected_checksum = self.header.checksum
        checksum = Segment._compute_checksum(self.header.with_checksum(0).encode() + self.data)
        return checksum == expected_checksum

    @staticmethod
    def decode(segment: bytes) -> "Segment":
        header_bytes = segment[: Header.HEADER_SIZE_BYTES]
        data = segment[Header.HEADER_SIZE_BYTES :]
        return Segment(
            header=Header.decode(header_bytes),
            data=data,
        )

    @staticmethod
    def create_ack(ack_num: int) -> "Segment":
        return Segment(
            header=Header(
                sequence_num=0,
                is_ack=True,
                ack_num=ack_num,
            ),
            data=b"",
        )

    @staticmethod
    def create_data_segment(sequence_num: int, data: bytes) -> "Segment":
        return Segment(
            header=Header(
                sequence_num=sequence_num,
                is_ack=False,
            ),
            data=data,
        )

    @staticmethod
    def _compute_checksum(packet: bytes) -> int:
        checksum_32bits = zlib.crc32(packet)
        checksum_16bits = checksum_32bits & 0xFFFF
        return checksum_16bits


# ==============================================================================
#                               End of dataclasses
# ==============================================================================

if __name__ == "__main__":
    main()
