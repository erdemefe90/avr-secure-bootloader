def crc16_ccitt(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
            crc &= 0xFFFF
    return crc

def hexdump(data: bytes, length=16):
    lines = []
    for i in range(0, len(data), length):
        chunk = data[i:i+length]
        hex_bytes = ' '.join(f"{b:02x}" for b in chunk)
        ascii_bytes = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        lines.append(f"{i:08x}  {hex_bytes:<48}  |{ascii_bytes}|")
    return '\n'.join(lines)
