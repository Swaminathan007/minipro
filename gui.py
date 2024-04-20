import sys
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QSizePolicy, QHeaderView
from PyQt6.QtCore import QTimer
import sysv_ipc
import json
from PyQt6.QtGui import QColor
import random
import datetime
import pytz
import subprocess
import threading

class CommandThread(threading.Thread):
    
    def run(self):
        commands = ["g++ capture.c -lpcap -lcjson -o cap.out", "sudo ./cap.out"]
        for command in commands:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)

class SimpleGUI(QWidget):
    def __init__(self):
        self.command_thread = CommandThread()
        self.command_thread.start()
        super().__init__()

        self.initUI()
        self.initMessageQueue()

    def initUI(self):
        self.setWindowTitle('Packet Capture')
        self.setGeometry(100, 100, 1000, 1000)

        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(['Timestamp', 'Source IP', 'Source port', 'Destination IP', 'Destination port', 'Classification'])

        layout = QVBoxLayout(self)
        layout.addWidget(self.table)
        self.setLayout(layout)
        
        self.table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.resizeTable()

    def initMessageQueue(self):
        self.message_queue_key = 1234
        self.max_message_size = 327680
        try:
            permissions = 0o666
            self.message_queue = sysv_ipc.MessageQueue(self.message_queue_key, sysv_ipc.IPC_CREAT, max_message_size=self.max_message_size, mode=permissions)
        except sysv_ipc.ExistentialError:
            self.message_queue = sysv_ipc.MessageQueue(self.message_queue_key)

        # Initialize QTimer to periodically check for new messages
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.receiveMessages)
        self.timer.start(1000)  # Set timer interval (milliseconds)

    def get_actual_time(self, times):
        utc_timestamp = datetime.datetime.utcfromtimestamp(times)
        local_timezone = pytz.timezone('Asia/Kolkata')
        local_timestamp = utc_timestamp.astimezone(local_timezone)
        local_timestamp = str(local_timestamp)
        local_timestamp = local_timestamp.split("+")[0]
        return local_timestamp

    def receiveMessages(self):
        try:
            while self.message_queue.current_messages > 0:
                message, msg_type = self.message_queue.receive()
                decoded = message.decode('utf-8')
                packet_json = json.loads(decoded)
                actual_time = self.get_actual_time(packet_json["Timestamp"])
                packet_json["Timestamp"] = actual_time
                classification = ["Normal", "Attack"]
                self.insertRow([packet_json.get('Timestamp', ''), packet_json["IP header"]["Source IP"], packet_json["Transport Header"]["Source port"], packet_json["IP header"]["Destination IP"], packet_json["Transport Header"]["Destination port"], random.choice(classification)])
        except Exception as e:
            print(f"Error receiving messages: {e}")

    def resizeTable(self):
        table_width = self.table.width()
        column_width = int(table_width / self.table.columnCount())
        for i in range(self.table.columnCount()):
            self.table.setColumnWidth(i, column_width)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.table.setMaximumSize(self.width(), self.height())
        self.resizeTable()

    def insertRow(self, data):
        row = self.table.rowCount()
        self.table.insertRow(row)
        for col, value in enumerate(data):
            item = QTableWidgetItem(str(value))
            if str(value) == "Normal":
                item.setBackground(QColor(0, 255, 0))
            elif str(value) == "Attack":
                item.setBackground(QColor(255, 0, 0))
            self.table.setItem(row, col, item)
        self.table.scrollToBottom()

def main():
    app = QApplication(sys.argv)
    window = SimpleGUI()
    window.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()

