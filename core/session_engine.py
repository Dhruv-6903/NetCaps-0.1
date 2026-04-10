"""5-tuple flow tracking with bounded payload buffering."""
from __future__ import annotations
import socket
import struct
from typing import Optional
import dpkt

import config
from core.data_model import Session, build_session_search

MB = 1024 * 1024


def _ip_str(addr: bytes) -> str:
    try:
        if len(addr) == 4:
            return socket.inet_ntoa(addr)
        return socket.inet_ntop(socket.AF_INET6, addr)
    except Exception:
        return addr.hex()


class SessionEngine:
    def __init__(self, cfg: dict | None = None) -> None:
        self._cfg = cfg or config.get()
        self._sessions: dict[str, Session] = {}
        self._global_bytes: int = 0
        self._global_cap: int = self._cfg.get("global_payload_cap_mb", 200) * MB
        self._per_cap: int = self._cfg.get("session_payload_cap_mb", 10) * MB

    @property
    def sessions(self) -> dict[str, Session]:
        return self._sessions

    # ------------------------------------------------------------------
    def process(self, ts: float, raw: bytes, link_type: int = 1) -> list[Session]:
        """Parse raw packet bytes and update sessions. Returns updated sessions."""
        updated: list[Session] = []
        try:
            if link_type == 1:
                eth = dpkt.ethernet.Ethernet(raw)
                ip = eth.data
            elif link_type == 101:
                ip = dpkt.ip.IP(raw)
            else:
                return updated

            if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                return updated

            src_ip = _ip_str(ip.src)
            dst_ip = _ip_str(ip.dst)
            proto_num = ip.p if hasattr(ip, "p") else ip.nxt

            transport = ip.data

            if isinstance(transport, dpkt.tcp.TCP):
                proto = "TCP"
                src_port = transport.sport
                dst_port = transport.dport
                payload = bytes(transport.data)
                flags = transport.flags
                session = self._get_or_create_tcp(
                    ts, src_ip, src_port, dst_ip, dst_port, flags
                )
                self._update_session(session, ts, src_ip, src_port, payload, flags)

            elif isinstance(transport, dpkt.udp.UDP):
                proto = "UDP"
                src_port = transport.sport
                dst_port = transport.dport
                payload = bytes(transport.data)
                session = self._get_or_create_udp(
                    ts, src_ip, src_port, dst_ip, dst_port
                )
                self._update_session(session, ts, src_ip, src_port, payload, 0)

            elif isinstance(transport, dpkt.icmp.ICMP):
                session = self._get_or_create_icmp(ts, src_ip, dst_ip)
                self._update_session(session, ts, src_ip, 0, b"", 0)

            elif isinstance(transport, dpkt.icmp6.ICMP6):
                session = self._get_or_create_icmp(ts, src_ip, dst_ip, proto="ICMPv6")
                self._update_session(session, ts, src_ip, 0, b"", 0)

            else:
                return updated

            updated.append(session)

        except Exception:
            pass
        return updated

    # ------------------------------------------------------------------
    def _make_session_id(self, proto: str, src_ip: str, src_port: int,
                          dst_ip: str, dst_port: int) -> tuple[str, bool]:
        """Return (session_id, is_client_to_server)."""
        if (src_ip, src_port) <= (dst_ip, dst_port):
            sid = f"{proto}:{src_ip}:{src_port}:{dst_ip}:{dst_port}"
            return sid, True
        else:
            sid = f"{proto}:{dst_ip}:{dst_port}:{src_ip}:{src_port}"
            return sid, False

    def _get_or_create_tcp(self, ts: float, src_ip: str, src_port: int,
                            dst_ip: str, dst_port: int, flags: int) -> Session:
        sid, is_client = self._make_session_id("TCP", src_ip, src_port, dst_ip, dst_port)
        if sid not in self._sessions:
            # Treat the SYN sender (or first seen) as client
            if flags & dpkt.tcp.TH_SYN and not (flags & dpkt.tcp.TH_ACK):
                c_ip, c_port, s_ip, s_port = src_ip, src_port, dst_ip, dst_port
            elif is_client:
                c_ip, c_port, s_ip, s_port = src_ip, src_port, dst_ip, dst_port
            else:
                c_ip, c_port, s_ip, s_port = dst_ip, dst_port, src_ip, src_port
            session = Session(
                session_id=sid, proto="TCP",
                src_ip=c_ip, src_port=c_port,
                dst_ip=s_ip, dst_port=s_port,
                start_time=ts, end_time=ts,
            )
            self._sessions[sid] = session
        return self._sessions[sid]

    def _get_or_create_udp(self, ts: float, src_ip: str, src_port: int,
                            dst_ip: str, dst_port: int) -> Session:
        sid, is_client = self._make_session_id("UDP", src_ip, src_port, dst_ip, dst_port)
        if sid not in self._sessions:
            c_ip, c_port, s_ip, s_port = (
                (src_ip, src_port, dst_ip, dst_port) if is_client
                else (dst_ip, dst_port, src_ip, src_port)
            )
            session = Session(
                session_id=sid, proto="UDP",
                src_ip=c_ip, src_port=c_port,
                dst_ip=s_ip, dst_port=s_port,
                start_time=ts, end_time=ts,
            )
            self._sessions[sid] = session
        return self._sessions[sid]

    def _get_or_create_icmp(self, ts: float, src_ip: str, dst_ip: str,
                             proto: str = "ICMP") -> Session:
        # For ICMP, use port 0
        sid, is_client = self._make_session_id(proto, src_ip, 0, dst_ip, 0)
        if sid not in self._sessions:
            c_ip, s_ip = (src_ip, dst_ip) if is_client else (dst_ip, src_ip)
            session = Session(
                session_id=sid, proto=proto,
                src_ip=c_ip, src_port=0,
                dst_ip=s_ip, dst_port=0,
                start_time=ts, end_time=ts,
            )
            self._sessions[sid] = session
        return self._sessions[sid]

    def _update_session(self, session: Session, ts: float, src_ip: str,
                         src_port: int, payload: bytes, flags: int) -> None:
        is_client = (src_ip == session.src_ip and src_port == session.src_port)
        pkt_len = len(payload)

        session.packets += 1
        session.end_time = ts
        session.duration = session.end_time - session.start_time

        if is_client:
            session.bytes_sent += pkt_len
        else:
            session.bytes_recv += pkt_len

        # Payload buffering with caps
        if not session.truncated and payload:
            if self._global_bytes < self._global_cap:
                if is_client:
                    if len(session.payload_client) + pkt_len <= self._per_cap:
                        session.payload_client += payload
                        self._global_bytes += pkt_len
                    else:
                        session.truncated = True
                else:
                    if len(session.payload_server) + pkt_len <= self._per_cap:
                        session.payload_server += payload
                        self._global_bytes += pkt_len
                    else:
                        session.truncated = True
            else:
                session.truncated = True

        # TCP state machine
        if session.proto == "TCP" and flags:
            if flags & dpkt.tcp.TH_RST:
                session.state = "RESET"
            elif flags & dpkt.tcp.TH_FIN:
                if session.state in ("ESTABLISHED", "NEW"):
                    session.state = "CLOSING"
                elif session.state == "CLOSING":
                    session.state = "CLOSED"
            elif flags & dpkt.tcp.TH_SYN and not (flags & dpkt.tcp.TH_ACK):
                session.state = "SYN"
            elif flags & dpkt.tcp.TH_SYN and flags & dpkt.tcp.TH_ACK:
                session.state = "SYN-ACK"
            elif flags & dpkt.tcp.TH_ACK and session.state == "SYN-ACK":
                session.state = "ESTABLISHED"
            elif session.state in ("NEW", "SYN", "SYN-ACK"):
                session.state = "ESTABLISHED"
        elif session.proto == "UDP":
            session.state = "ESTABLISHED"

        session._search_str = build_session_search(session)

    def finalize_all(self) -> None:
        for s in self._sessions.values():
            if s.state not in ("CLOSED", "RESET"):
                if s.proto == "TCP":
                    s.state = "INCOMPLETE"
