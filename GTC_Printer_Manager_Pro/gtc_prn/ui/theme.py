STYLE = """
* { font-family: 'Segoe UI', 'Noto Sans', sans-serif; font-size: 10pt; }
QMainWindow, QWidget { background: #f5f7fa; color: #1f2937; }
QLabel { background: transparent; }
QTabWidget::pane { border: 1px solid #d1d5db; background: #ffffff; }
QTabBar::tab { padding: 8px 16px; background: #e5e7eb; border: 1px solid #d1d5db; border-bottom: none; }
QTabBar::tab:selected { background: #ffffff; font-weight: 600; }
QTabBar::tab:focus { border: 2px solid #1f6feb; }
QPushButton { padding: 7px 14px; border: 1px solid #9ca3af; border-radius: 4px; background: #ffffff; }
QPushButton:hover { background: #eef2ff; }
QPushButton:focus { border: 2px solid #1f6feb; }
QPushButton:disabled { color: #9ca3af; background: #f3f4f6; }
QPushButton#primary { background: #1f6feb; color: white; font-size: 12pt; font-weight: 600; padding: 12px 28px; border: none; }
QPushButton#primary:hover { background: #1558c0; }
QPushButton#primary:disabled { background: #93b4ee; color: #eef2ff; }
QLineEdit, QPlainTextEdit, QSpinBox, QComboBox, QTableView, QListWidget { background: #ffffff; border: 1px solid #d1d5db; border-radius: 3px; }
QLineEdit:focus, QPlainTextEdit:focus, QSpinBox:focus, QComboBox:focus, QTableView:focus { border: 2px solid #1f6feb; }
QHeaderView::section { background: #1f4e79; color: white; padding: 6px; border: none; border-right: 1px solid #3b6ea5; }
QTableView { gridline-color: #e5e7eb; selection-background-color: #bfdbfe; selection-color: #111827; alternate-background-color: #f9fafb; }
QFrame#card { background: #ffffff; border: 1px solid #d1d5db; border-radius: 6px; }
QLabel#kpiValue { font-size: 16pt; font-weight: 700; color: #1f4e79; }
QLabel#kpiTitle { color: #6b7280; }
QLabel#warn { background: #fff7e6; border: 1px solid #f5c26b; color: #7a4a00; padding: 6px; border-radius: 4px; }
QLabel#note { color: #6b7280; }
QProgressBar { border: 1px solid #d1d5db; border-radius: 4px; text-align: center; background: #fff; height: 18px; }
QProgressBar::chunk { background: #1f6feb; }
"""
