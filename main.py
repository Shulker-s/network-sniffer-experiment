import sys, time, traceback
from datetime import datetime
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QComboBox, QLineEdit, QTableWidget, QTableWidgetItem, QSplitter, QPlainTextEdit, QMessageBox, QDialog)
from scapy.all import AsyncSniffer, get_if_list, conf, wrpcap
from scapy.interfaces import resolve_iface
from core import parse, matches, process_snapshot, stream_text

class Capture(QThread):
    packet = Signal(object); error = Signal(str)
    def __init__(self, iface, bpf): super().__init__(); self.iface=iface; self.bpf=bpf; self.sniffer=None; self.stopping=False
    def run(self):
        try:
            def deliver(packet):
                self.packet.emit(packet)
            options=dict(iface=self.iface, prn=deliver, store=False)
            if self.bpf: options['filter']=self.bpf
            self.sniffer=AsyncSniffer(**options); self.sniffer.start()
            while not self.stopping and self.sniffer.running: self.msleep(100)
            if self.sniffer.running: self.sniffer.stop()
            if self.sniffer.exception: raise self.sniffer.exception
        except Exception as e: self.error.emit(str(e))
    def stop(self): self.stopping=True

class Window(QMainWindow):
    def __init__(self):
        super().__init__(); self.setWindowTitle('网络嗅探器 - 实验 1A'); self.resize(1400,850)
        self.records=[]; self.visible=[]; self.mapping={}; self.capture=None; self.limit=10000
        root=QWidget(); self.setCentralWidget(root); layout=QVBoxLayout(root)
        row=QHBoxLayout(); layout.addLayout(row); row.addWidget(QLabel('网卡'))
        self.iface=QComboBox(); row.addWidget(self.iface,2)
        for i in get_if_list():
            try: info=resolve_iface(i); label=f'{info.description}  ({i})'
            except Exception: label=i
            self.iface.addItem(label,i)
        self.start=QPushButton('开始抓包'); self.start.clicked.connect(self.start_capture); row.addWidget(self.start)
        self.stop=QPushButton('停止'); self.stop.clicked.connect(self.stop_capture); self.stop.setEnabled(False); row.addWidget(self.stop)
        clear=QPushButton('清空'); clear.clicked.connect(self.clear); row.addWidget(clear)
        save=QPushButton('导出 PCAP'); save.clicked.connect(self.save); row.addWidget(save)
        filt=QHBoxLayout(); layout.addLayout(filt); filt.addWidget(QLabel('捕获过滤 BPF'))
        self.bpf=QLineEdit(); self.bpf.setPlaceholderText('可留空；例：tcp or udp'); filt.addWidget(self.bpf)
        filt.addWidget(QLabel('显示协议')); self.protocol=QComboBox(); self.protocol.addItems(['全部','TCP','UDP','IPv4','IPv6','ICMP','HTTP']); filt.addWidget(self.protocol)
        self.query=QLineEdit(); self.query.setPlaceholderText('地址、端口、进程名或 PID'); filt.addWidget(self.query)
        self.protocol.currentTextChanged.connect(self.refresh); self.query.textChanged.connect(self.refresh)
        stream=QPushButton('查看选中 TCP 流'); stream.clicked.connect(self.show_stream); filt.addWidget(stream)
        split=QSplitter(Qt.Vertical); layout.addWidget(split)
        self.table=QTableWidget(0,8); self.table.setHorizontalHeaderLabels(['序号','时间','源地址','目的地址','协议','长度','端口 源 → 目的','进程 / PID']); self.table.setSelectionBehavior(QTableWidget.SelectRows); self.table.setEditTriggers(QTableWidget.NoEditTriggers); self.table.horizontalHeader().setStretchLastSection(True); self.table.itemSelectionChanged.connect(self.selected); split.addWidget(self.table)
        lower=QSplitter(Qt.Horizontal); split.addWidget(lower); self.detail=QPlainTextEdit(); self.detail.setReadOnly(True); lower.addWidget(self.detail); self.hex=QPlainTextEdit(); self.hex.setReadOnly(True); lower.addWidget(self.hex); split.setSizes([500,300])
        self.statusBar().showMessage('请选择网卡。只捕获获授权的流量。')
        self.timer=QTimer(self); self.timer.timeout.connect(self.update_process); self.timer.start(1000); self.update_process()
    def update_process(self): self.mapping=process_snapshot()
    def start_capture(self):
        if self.iface.currentData() is None: QMessageBox.warning(self,'网卡','没有可用网卡，请检查 Npcap。'); return
        self.capture=Capture(self.iface.currentData(),self.bpf.text().strip()); self.capture.packet.connect(self.add_packet); self.capture.error.connect(self.capture_error); self.capture.finished.connect(self.finished); self.capture.start(); self.start.setEnabled(False); self.stop.setEnabled(True); self.statusBar().showMessage('正在抓包')
    def capture_error(self,e): QMessageBox.critical(self,'抓包失败',f'{e}\n检查 Npcap、管理员权限、网卡和 BPF 语法。')
    def finished(self): self.start.setEnabled(True); self.stop.setEnabled(False); self.statusBar().showMessage(f'已停止；保留 {len(self.records)} 个包')
    def stop_capture(self):
        if self.capture: self.capture.stop(); self.stop.setEnabled(False)
    def add_packet(self,p):
        try:
            r=parse(p)
            if r.flow in self.mapping: r.pid,r.process=self.mapping[r.flow]
            self.records.append(r)
            if len(self.records)>self.limit: self.records.pop(0); self.refresh()
            elif matches(r,self.protocol.currentText(),self.query.text()): self.add_row(r)
            self.statusBar().showMessage(f'抓包中：保留 {len(self.records)} 个包，显示 {len(self.visible)} 个；上限 {self.limit}')
        except Exception as e: self.statusBar().showMessage(f'解析异常：{e}')
    def add_row(self,r):
        n=self.table.rowCount(); self.table.insertRow(n); self.visible.append(r)
        vals=[str(n+1),datetime.fromtimestamp(float(r.packet.time)).strftime('%H:%M:%S.%f')[:-3],r.src,r.dst,r.protocol,str(len(r.packet)),f'{r.sport} → {r.dport}' if r.sport else '-',f'{r.process} / {r.pid}' if r.pid else '未知']
        for col,v in enumerate(vals): self.table.setItem(n,col,QTableWidgetItem(v))
    def refresh(self,*args):
        self.table.setRowCount(0); self.visible=[]
        for r in self.records:
            if matches(r,self.protocol.currentText(),self.query.text()): self.add_row(r)
    def selected(self):
        row=self.table.currentRow()
        if 0<=row<len(self.visible):
            p=self.visible[row].packet; self.detail.setPlainText(p.show(dump=True)); raw=bytes(p); self.hex.setPlainText('\n'.join(f'{i:04x}  '+ ' '.join(f'{x:02x}' for x in raw[i:i+16]) for i in range(0,len(raw),16)))
    def show_stream(self):
        row=self.table.currentRow()
        if not 0<=row<len(self.visible) or not self.visible[row].flow: QMessageBox.information(self,'TCP 流','请选择 TCP 数据包。'); return
        r=self.visible[row]; dialog=QDialog(self); dialog.setWindowTitle('TCP 双向流（仅已捕获数据）'); dialog.resize(900,600); layout=QVBoxLayout(dialog); layout.addWidget(QLabel('按序列号重组；缺包会标注。端口复用可能合并连接，内容可能不完整。')); box=QPlainTextEdit(); box.setReadOnly(True); box.setPlainText(stream_text(self.records,r.flow)); layout.addWidget(box); dialog.exec()
    def clear(self): self.records=[]; self.refresh(); self.detail.clear(); self.hex.clear()
    def save(self):
        from PySide6.QtWidgets import QFileDialog
        path,_=QFileDialog.getSaveFileName(self,'导出','capture.pcap','PCAP (*.pcap)')
        if path:
            try: wrpcap(path,[r.packet for r in self.records])
            except Exception as e: QMessageBox.warning(self,'导出失败',str(e))
    def closeEvent(self,event):
        if self.capture and self.capture.isRunning(): self.capture.stop(); self.capture.wait(3000)
        event.accept()

if __name__=='__main__':
    app=QApplication(sys.argv); w=Window(); w.show(); sys.exit(app.exec())

