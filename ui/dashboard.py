"""Mini dashboard with 3 charts."""
from __future__ import annotations
import time
from collections import defaultdict
from PySide6.QtWidgets import QWidget, QHBoxLayout, QLabel, QVBoxLayout
from PySide6.QtCore import Qt

try:
    import pyqtgraph as pg
    _HAS_PG = True
except ImportError:
    _HAS_PG = False


class Dashboard(QWidget):
    def __init__(self, case_store, parent=None) -> None:
        super().__init__(parent)
        self._store = case_store
        self._setup_ui()
        self.setMaximumHeight(220)

    def _setup_ui(self) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(8)

        if _HAS_PG:
            self._traffic_plot = pg.PlotWidget(title="Traffic (KB/s)")
            self._traffic_plot.setLabel("bottom", "Time (s)")
            self._traffic_plot.setLabel("left", "KB/s")
            self._traffic_curve = self._traffic_plot.plot(pen=pg.mkPen("cyan", width=2))
            layout.addWidget(self._traffic_plot)

            self._proto_plot = pg.PlotWidget(title="Protocol Distribution")
            self._proto_bars = None
            layout.addWidget(self._proto_plot)

            self._top_ips_plot = pg.PlotWidget(title="Top IPs (bytes)")
            self._top_bars = None
            layout.addWidget(self._top_ips_plot)
        else:
            layout.addWidget(QLabel("Install pyqtgraph for charts"))

    def refresh(self) -> None:
        if not _HAS_PG:
            return
        try:
            self._refresh_traffic()
            self._refresh_proto()
            self._refresh_top_ips()
        except Exception:
            pass

    def _refresh_traffic(self) -> None:
        sessions = self._store.snapshot_sessions()
        if not sessions:
            return
        times: dict[int, int] = defaultdict(int)
        for s in sessions:
            t = int(s.start_time)
            times[t] += s.bytes_sent + s.bytes_recv
        if not times:
            return
        xs = sorted(times.keys())
        t0 = xs[0]
        x = [t - t0 for t in xs]
        y = [times[t] / 1024.0 for t in xs]
        self._traffic_curve.setData(x, y)

    def _refresh_proto(self) -> None:
        sessions = self._store.snapshot_sessions()
        if not sessions:
            return
        counts: dict[str, int] = defaultdict(int)
        for s in sessions:
            counts[s.proto] += 1

        self._proto_plot.clear()
        if not counts:
            return
        protos = list(counts.keys())
        vals = [counts[p] for p in protos]
        bar_item = pg.BarGraphItem(x=list(range(len(protos))), height=vals, width=0.6,
                                    brush="steelblue")
        self._proto_plot.addItem(bar_item)
        ax = self._proto_plot.getAxis("bottom")
        ax.setTicks([list(enumerate(protos))])

    def _refresh_top_ips(self) -> None:
        hosts = self._store.snapshot_hosts()
        if not hosts:
            return
        top = sorted(hosts, key=lambda h: h.bytes_sent + h.bytes_recv, reverse=True)[:10]
        labels = [h.ip for h in top]
        vals = [(h.bytes_sent + h.bytes_recv) / 1024.0 for h in top]

        self._top_ips_plot.clear()
        bar_item = pg.BarGraphItem(x=list(range(len(labels))), height=vals, width=0.6,
                                    brush="orange")
        self._top_ips_plot.addItem(bar_item)
        ax = self._top_ips_plot.getAxis("bottom")
        ax.setTicks([list(enumerate(labels))])
