import struct
import zlib
from dataclasses import dataclass
from tabnanny import check
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

    def set_checksum(self, checksum: int) -> "Header":
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
        checksum = Segment.compute_checksum(self.header.encode() + self.data)
        return self.header.set_checksum(checksum).encode() + self.data

    def has_no_bit_error(self) -> bool:
        expected_checksum = self.header.checksum
        checksum = Segment.compute_checksum(self.header.set_checksum(0).encode() + self.data)
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
    def compute_checksum(packet: bytes) -> int:
        checksum_32bits = zlib.crc32(packet)
        checksum_16bits = checksum_32bits & 0xFFFF
        return checksum_16bits

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
