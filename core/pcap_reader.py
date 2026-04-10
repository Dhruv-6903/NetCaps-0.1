"""PCAP / PCAPNG reader that yields (timestamp, raw_bytes) tuples."""
from __future__ import annotations
import io
import struct
from pathlib import Path
from typing import Iterator


def iter_packets(filepath: str) -> Iterator[tuple[float, bytes]]:
    """Yield (timestamp: float, raw_data: bytes) for each packet."""
    path = Path(filepath)
    data = path.read_bytes()
    if len(data) < 4:
        return

    magic = struct.unpack_from("<I", data, 0)[0]

    # PCAPNG magic
    if magic == 0x0A0D0D0A:
        yield from _iter_pcapng(data)
    else:
        yield from _iter_pcap(filepath)


def _iter_pcap(filepath: str) -> Iterator[tuple[float, bytes]]:
    """Parse classic PCAP using dpkt."""
    import dpkt
    try:
        with open(filepath, "rb") as f:
            try:
                reader = dpkt.pcap.Reader(f)
            except Exception:
                return
            for ts, buf in reader:
                yield float(ts), buf
    except Exception:
        return


def _iter_pcapng(data: bytes) -> Iterator[tuple[float, bytes]]:
    """Minimal PCAPNG reader supporting IDB, EPB, SPB, and obsolete Packet blocks."""
    offset = 0
    length = len(data)
    if_tsresol: dict[int, float] = {}  # interface id -> timestamp resolution factor
    link_types: dict[int, int] = {}

    while offset + 8 <= length:
        block_type = struct.unpack_from("<I", data, offset)[0]
        if offset + 12 > length:
            break
        block_len = struct.unpack_from("<I", data, offset + 4)[0]
        if block_len < 12 or offset + block_len > length:
            break

        block_body = data[offset + 8 : offset + block_len - 4]

        if block_type == 0x0A0D0D0A:
            # Section Header Block - reset interface list
            if_tsresol.clear()
            link_types.clear()

        elif block_type == 0x00000001:
            # Interface Description Block
            iface_id = len(if_tsresol)
            if len(block_body) >= 4:
                link_types[iface_id] = struct.unpack_from("<H", block_body, 0)[0]
            resol = _parse_tsresol_option(block_body[4:] if len(block_body) > 4 else b"")
            if_tsresol[iface_id] = resol

        elif block_type == 0x00000006:
            # Enhanced Packet Block
            if len(block_body) >= 20:
                iface_id = struct.unpack_from("<I", block_body, 0)[0]
                ts_high = struct.unpack_from("<I", block_body, 4)[0]
                ts_low = struct.unpack_from("<I", block_body, 8)[0]
                cap_len = struct.unpack_from("<I", block_body, 12)[0]
                ts_raw = (ts_high << 32) | ts_low
                resol = if_tsresol.get(iface_id, 1e-6)
                ts = ts_raw * resol
                pkt_data = block_body[20 : 20 + cap_len]
                yield ts, pkt_data

        elif block_type == 0x00000003:
            # Simple Packet Block
            if len(block_body) >= 4:
                orig_len = struct.unpack_from("<I", block_body, 0)[0]
                pkt_data = block_body[4:]
                yield 0.0, pkt_data

        elif block_type == 0x00000002:
            # Obsolete Packet Block
            if len(block_body) >= 20:
                iface_id = struct.unpack_from("<H", block_body, 0)[0]
                ts_high = struct.unpack_from("<H", block_body, 2)[0]
                ts_low = struct.unpack_from("<I", block_body, 4)[0]
                cap_len = struct.unpack_from("<I", block_body, 8)[0]
                ts_raw = (ts_high << 32) | ts_low
                resol = if_tsresol.get(iface_id, 1e-6)
                ts = ts_raw * resol
                pkt_data = block_body[16 : 16 + cap_len]
                yield ts, pkt_data

        offset += block_len


def _parse_tsresol_option(options: bytes) -> float:
    """Return seconds-per-tick from tsresol option (default 1e-6)."""
    i = 0
    while i + 4 <= len(options):
        code = struct.unpack_from("<H", options, i)[0]
        opt_len = struct.unpack_from("<H", options, i + 2)[0]
        i += 4
        if code == 0:  # opt_endofopt
            break
        if code == 9 and opt_len >= 1:  # if_tsresol
            raw = options[i]
            if raw & 0x80:
                resol = 10 ** -(raw & 0x7F)
            else:
                resol = 2 ** -(raw & 0x7F)
            return resol
        # align to 32-bit
        i += (opt_len + 3) & ~3
    return 1e-6
