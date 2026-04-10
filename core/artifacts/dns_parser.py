"""DNS artifact parser."""
from __future__ import annotations
from typing import Iterator
import dpkt

from core.data_model import DnsEvent, build_dns_search

_QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA",
    12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
    33: "SRV", 255: "ANY",
}

_RCODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL",
    3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
}


def _decode_name(name: bytes) -> str:
    try:
        return name.decode("utf-8", errors="replace")
    except Exception:
        return str(name)


def parse_dns_payload(ts: float, src_ip: str, payload: bytes) -> DnsEvent | None:
    try:
        dns = dpkt.dns.DNS(payload)
    except Exception:
        return None

    if not dns.qd:
        return None

    q = dns.qd[0]
    query = _decode_name(q.name)
    qtype = _QTYPES.get(q.type, str(q.type))
    status = _RCODES.get(dns.rcode, str(dns.rcode))

    responses: list[str] = []
    for rr in list(dns.an) + list(dns.ns) + list(dns.ar):
        try:
            rdata = rr.rdata
            if isinstance(rdata, bytes) and len(rdata) == 4:
                import socket
                responses.append(socket.inet_ntoa(rdata))
            elif isinstance(rdata, bytes) and len(rdata) == 16:
                import socket
                responses.append(socket.inet_ntop(socket.AF_INET6, rdata))
            elif hasattr(rr, "name") and rr.type == 5:
                responses.append(_decode_name(rr.cname if hasattr(rr, "cname") else rdata))
            else:
                responses.append(str(rdata))
        except Exception:
            pass

    evt = DnsEvent(
        ts=ts,
        src_ip=src_ip,
        query=query,
        qtype=qtype,
        responses=responses,
        status=status,
    )
    evt._search_str = build_dns_search(evt)
    return evt
