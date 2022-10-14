from enum import Enum
import socket
import struct
import time


class ICMP_Echo_Type(Enum):
    ECHO = 8
    REPLY = 0


class ICMP_Echo():
    """
    ICMP packet per RFC 792 pg. 14
    Type (8 bits), Code (8 bits), Checksum (16 bits), Identifier (16 bits), Sequence Number (16 bits), Data (n bytes)
    Checksum per RFC 1071
    """

    def __init__(self, icmp_type: ICMP_Echo_Type = ICMP_Echo_Type.ECHO, code: int = 0, identifier: int = 1, sequence: int = 1, data: bytes = b"abcdefghijklmnopqrstuvwabcdefghi"):
        self.icmp_type: ICMP_Echo_Type = icmp_type
        self.code: int = code
        self.checksum = 0  # 0 until calculated
        self.identifier: int = identifier
        self.sequence: int = sequence
        self.data: bytes = data
        self.response_time = -1
        self.set_checksum()

    def __bytes__(self):
        self.set_checksum()
        return struct.pack(f"!BBHHH{len(self.data)}s", self.icmp_type.value, self.code, self.checksum, self.identifier, self.sequence, self.data)    
    
    def __repr__(self):
        return f"ICMP_Echo(icmp_type={self.icmp_type}, code={self.code}, checksum={self.checksum} ({'good' if self.check_checksum() else 'bad'}), identifier={self.identifier}, sequence={self.sequence}, data={self.data.hex(' ')})"
    
    @classmethod
    def from_bytes(cls, packet):
        type_val, code, checksum, identifier, sequence = struct.unpack("!BBHHH", packet[:8])
        data = packet[8:]
        return cls(ICMP_Echo_Type(type_val), code, identifier, sequence, data)

    def calculate_checksum(self) -> int:
        # Generate the payload with 0 in place of the checksum
        payload = struct.pack(f"!BBHHH{len(self.data)}s", self.icmp_type.value, self.code, 0, self.identifier, self.sequence, self.data)

        # If odd length of bytes, append a 0 to make the length even
        if len(payload) % 2 == 1:
            payload += b"\x00"
        
        # Sum the payload in 16 bit increments
        s = 0
        for i in range(0, len(payload), 2):
            a = payload[i]
            b = payload[i+1]
            s += (a << 8) + b

        # Take the high 16 bits, right shift 16, then sum to low bits.  Do it twice.
        s = (s >> 16) + (s & 0xFFFF)  # Add high bits to low bits
        s += s >> 16
        return ~s & 0xFFFF
    
    def check_checksum(self) -> bool:
        return self.checksum == self.calculate_checksum()
    
    def set_checksum(self, override = None):
        if override is not None:
            self.checksum = override
        else:
            self.checksum = self.calculate_checksum()
    
    def sendto(self, dest: str):
        """Returns a new ICMP_Echo, typically with the icmp_type set to REPLY.  Returns None if the destination didn't reply to the ICMP Echo request"""
        if self.icmp_type != ICMP_Echo_Type.ECHO:
            print(f"[Warning] Expected to send an ICMP Echo, got {self.icmp_type}.")
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(4)  # TODO this might be something that should be configurable
        try:
            sock.connect((dest, 0))
        except socket.gaierror:
            return None
        except OSError:
            return None
        icmp_payload = bytes(self)
        # Must just be .send and .recv in the timing block
        t1 = time.perf_counter()
        sock.send(icmp_payload)
        try:
            received = sock.recv(2 ** 16)
        except TimeoutError as e:
            return None
        except socket.timeout:  # Somehow escapes the first except block in rare edge cases?
            return None
        t2 = time.perf_counter()
        received = received[20:]  # Snip off the first 20 bytes, they're the IP header from the raw socket I think
        # End of timing block
        response = ICMP_Echo.from_bytes(received)
        response.response_time = t2 - t1
        return response


def ping(target: str) -> float:
    """Ping an address and return the number of seconds as a float that the ping took."""
    Echo = ICMP_Echo()
    response = Echo.sendto(target)
    if response is not None:
        return response.response_time
    else:
        return -1
