#!/usr/bin/env python3

import sys
import os
import platform
import time
import threading
import subprocess
import tempfile
import hashlib
import json
import re
import unicodedata
import shutil
import requests
import uuid
import secrets
import xml.sax.saxutils as saxutils
import datetime
from types import SimpleNamespace
from pathlib import Path
from unidecode import unidecode
import traceback

app_version = "2.1"

try:
    log_path = Path.cwd() / "menjmoi.log"
    with open(log_path, "w", encoding="utf-8") as f:
        pass
except Exception:
    try:
        with open("menjmoi.log", "w", encoding="utf-8") as f:
            pass
    except Exception:
        pass

IS_WIN = (os.name == 'nt')

def _safe_subprocess_kwargs():
    return {}

def _win_no_window_kwargs():
    return {}

APP_LOGO_BASE64 = (
    "AAABAAEAICAAAAEAIACoEAAAFgAAACgAAAAgAAAAQAAAAAEAIAAAAAAAABAAAMMOAADDDgAAAAAAAAAAAAD///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////b29v/19fX/7u7u/+/v7//q6ur/8PDw/+vr6//y8vL/7e3t/+/v7//w8PD/6urq/+/v7//v7+//8PDw/+3t7f/y8vL/8/Pz//7+/v//////////////////////////////////////////////////////////////////////wcHB/8HBwf+jo6P/sLCw/6SkpP+vr67/nJya/7Cxr/+qqqj/sbGw/8PDw/9/f3//p6en/5GRkf+qqqr/jo6O/6ampv+kpKT/+/v7//////////////////////////////////////////////////////////////////39/f/Q0ND/29vb/9fX1//Z2dj/3d3e/8vL2P+urcn/tbTZ/7W02P+7utP/0dDa/9DQ0P/f397/2NjY/9zc3P/V1dX/3d3d/9zc3P/9/f3/////////////////////////////////////////////////////////////////////////////////9PP+/7y69P93cuj/SkTg/zgy3f8zLdv/My3b/zo03f9STOH/h4Pr/8zK9//6+v7//////////////////////////////////////////////////////////////////////////////////////////////////f3//8XD9f9bVuH/KyXZ/0lD3v99eej/paLv/7e18v+1s/L/oJ3u/3Rv5v8/Odz/LyjZ/3Fs5f/Z2Pj///////////////////////////////////////////////////////////////////////////////////////r5/v+em+7/MSra/0tF3/+tqvD/3dz5//n5/v///////////////////////f3//+bl+v+bmO3/OzXc/z853P+6uPP//v7////////////////////////////////////////////////////////////////////////9/f//mpft/ykj2f9zb+b/6Of7/+7u/P9gW+L/ravw///////////////////////////////////////W1fj/WlTh/zMs2v+4tvL//////////////////////////////////////////////////////////////////////7u58/8uKNn/eXXn//Pz/f//////1dT3/y0n2f+Yle3////////////////////////////////////////////l5Pr/WFPh/zw23P/V1Pj////////////////////////////////////////////////////////////s6/z/T0nf/1ZR4f/r6/v///////////+6uPP/KiPZ/7278//////////////////////////////////////////////////T0vf/ODHb/2xn5P/4+P7//////////////////////////////////////////////////////6ek7/8tJtn/v730/////////////////6Kg7v8tJtn/0dD3//////////////////b1/f+4tvL/iYXq/66s8P/39/7///////////+QjOv/KSLY/8bE9f/////////////////////////////////////////////////4+P7/Xlni/1xX4v/29v3/////////////////kY7r/y0m2f/V1Pf////////////8/P7/jYrr/yYf2P8dFtb/Jh/Y/5yZ7f///////////9va+P91ceb/0tH3/////////////////////////////////////////////////+Df+f84Mtv/m5jt//////////////////////+IhOr/KiTZ/9HQ9////////////8nH9f8vKdr/HxjX/yAZ1/8fGNf/PTfc/9/e+f///////f3///z7/v/29v3/29r5/+3s/P//////////////////////////////////////xcT1/zAp2v/EwvT//////////////////////4WC6f8kHdj/wsD0///////+/v//fHjn/x0W1v8mH9j/Lyna/yAZ1/8kHdj/u7nz/////////////f3//4yJ6v8yK9r/VE/g/93c+f////////////////////////////////+2s/L/My3a/9bV+P//////////////////////jYrr/x4W1v+npO///////+np+/9FP93/HBXW/2hj5P93c+b/HhfW/yIb1/+vrPD////////////r6vv/RD7d/x0W1v8hGtf/trTy/////////////////////////////////7Ow8f80Ltv/2dj4//////////////////////+hnu7/HBXW/3t35///////wsD0/ygh2P8kHdj/t7Ty/4J+6f8dFtb/IBnX/6Ge7v///////////9TT9/8wKtr/IBnX/ygh2P/DwfT/////////////////////////////////v73z/zAq2v/Kyfb//////////////////////8LA9P8mH9j/RT/d/+jo+/+Mier/HRbW/zo03P/g3/n/eHTn/x0W1v8eF9f/lJHs////////////s7Dx/yMc1/8gGNf/NS/b/9zb+f/////////////////////////////////a2Pj/NC7a/6Og7v//////////////////////6en7/0ZA3v8hGtf/b2vl/0E73f8cFNb/Xlni//f2/f9uaeX/HRbW/x4X1v+Khur///////////+Jher/HhfW/x4X1/9MR9//8O/8//////////////////////////////////X1/f9WUeD/Yl3j//j4/v//////////////////////mpft/yIb1/8cFdb/HhfW/yQd2P+ope///v7//2di5P8dFtb/HRbW/4J+6P//////+Pj+/15Z4v8eF9b/HRbW/25p5f/9/f///////////////////////////////////////52a7f8tJtn/wsD0///////////////////////08/3/j4zr/0I83f87Ndz/iYXq//b1/f/7+/7/Y17j/x0W1v8dFtb/fHjn///////h4Pr/OzXc/x8Y1/8fGNf/mZbt////////////////////////////////////////////5uX6/0ZB3v9WUeD/6un7///////////////////////9/P//6ej7/+Tj+v/6+v7///////r6/v9hXOP/HRbW/x0W1v96duf//////7m38v8lH9j/IBnX/yok2f/HxfX/////////////////////////////////////////////////r63x/ygh2P90cOb/8O/8////////////////////////////////////////////+/v+/2Vg4/8dFtb/HRbW/3t25///////g4Dp/x4X1v8fF9f/SUPe/+zs/P/////////////////////////////////////////////////6+v7/i4fq/yQd1/9rZuT/3975///////////////////////////////////////+/v//cGvl/x0W1v8dFtb/eXXn/+7t/P9MRt//HhfX/x4X1v+Bfej////////////////////////////////////////////////////////////19f3/iYbq/yYf2P9BO93/n5zu/+Tj+v/8/P7///////////////////////////+EgOn/HRbW/x0W1v9uaeX/sa/x/ycg2P8gGdf/LCbZ/8fF9f/////////////////////////////////////////////////////////////////5+f7/q6nw/0I83f8hGtf/PDbc/2xn5P+TkOz/pqPv/6qn8P+opfD/0tD3/6aj7/8hGtf/IBnX/zMt2v87Ndz/IBnX/x4W1v9oZOT/9/f+////////////////////////////////////////////////////////////////////////////4uL6/5aS7P9QS+D/LSbZ/yEa1/8gGdf/IRrX/yYf2P94dOf/0dD3/zIr2v8gGdf/IBnX/x8Y1/8fGNf/NS/b/8vK9v////////////////////////////////////////////////////////////////////////////////////////////Ly/f/U0vf/t7Xy/6il7/+sqvD/xcP1/+Xk+v/5+f7/d3Pn/x0W1v8dFtb/HRbW/zIs2v+rqPD//v7////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////n5/v/jYnq/2xn5P+Cfuj/yMf1//39/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////f3/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
)

def get_app_logo_pixmap():
    import base64
    from PySide6.QtGui import QPixmap
    logo_data = base64.b64decode(APP_LOGO_BASE64)
    pixmap = QPixmap()
    pixmap.loadFromData(logo_data)
    return pixmap

USER_INFO = {"user_name": None, "expiry_date": None}

def in_ra_loi_khong_dau(msg, exc=None):
    try:
        log_path = Path.cwd() / "menjmoi.log"
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        msg = str(msg)
        msg = unicodedata.normalize("NFD", msg)
        msg = "".join(ch for ch in msg if not unicodedata.category(ch).startswith("M"))
        msg = msg.replace("đ", "d").replace("Đ", "D")
        if exc is not None:
            with open(log_path, "a", encoding="utf-8", buffering=1) as f:
                f.write(f"[{now}] {msg}\n")
                f.write(f"[{now}] Chi tiet loi:\n")
                traceback.print_exception(type(exc), exc, exc.__traceback__, file=f)
    except Exception as e:
        try:
            with open("menjmoi.log", "a", encoding="utf-8", buffering=1) as f:
                f.write(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Loi in ra loi: {e}\n")
        except Exception:
            pass

def get_machine_guid():
    if not IS_WIN:
        return ""
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography")
        value, _ = winreg.QueryValueEx(key, "MachineGuid")
        return value
    except Exception as e:
        in_ra_loi_khong_dau(f"Loi lay MachineGuid: {e}", e)
        return ""

def get_computer_name():
    try:
        return os.environ.get("COMPUTERNAME") or platform.node() or ""
    except Exception as e:
        in_ra_loi_khong_dau(f"Loi lay COMPUTERNAME: {e}", e)
        return ""

def get_real_mac():
    try:
        mac = None
        if IS_WIN:
            res = run_subproc(["getmac", "/fo", "csv", "/nh"], timeout=10)
            lines = (res.stdout if res else "").splitlines()
            for line in lines:
                parts = [x.strip('"') for x in line.split(",")]
                if len(parts) >= 2 and re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", parts[0]):
                    mac = parts[0]
                    break
        else:
            for iface in os.listdir('/sys/class/net/'):
                if iface == "lo":
                    continue
                try:
                    with open(f"/sys/class/net/{iface}/address") as f:
                        mac_addr = f.read().strip()
                        if mac_addr and mac_addr != "00:00:00:00:00:00":
                            mac = mac_addr
                            break
                except Exception:
                    continue
        if not mac:
            mac = ':'.join(['%02x' % ((uuid.getnode() >> ele) & 0xff) for ele in range(40, -8, -8)])
        return mac or ""
    except Exception as e:
        in_ra_loi_khong_dau(f"Loi lay MAC that: {e}", e)
        return ""

def get_fingerprint():
    if IS_WIN:
        mguid = get_machine_guid()
        cname = get_computer_name()
        mac = get_real_mac()
        fp = f"{mguid}|{cname}|{mac}"
        return fp
    else:
        try:
            if os.path.isfile("/etc/machine-id"):
                with open("/etc/machine-id", "r") as f:
                    mid = f.read().strip()
            else:
                mid = ""
        except Exception:
            mid = ""
        node = platform.node()
        mac = get_real_mac()
        fp = f"{mid}|{node}|{mac}"
        return fp

try:
    import cv2
    DEBUG_MODE = ('--debug' in sys.argv)

    def _relaunch_with_pythonw_if_possible() -> bool:
        if os.name != 'nt' or DEBUG_MODE:
            return False
        try:
            exe = Path(sys.executable)
            if exe.name.lower() == 'pythonw.exe':
                return False
            pyw = exe.with_name('pythonw.exe')
            if pyw.exists():
                script = Path(sys.argv[0]).resolve()
                args = [str(pyw), str(script)] + [a for a in sys.argv[1:] if a != '--debug']
                subprocess.Popen(args, close_fds=True)
                os._exit(0)
            return False
        except Exception:
            return False

    def _hide_and_detach_console_permanently():
        if os.name != 'nt' or DEBUG_MODE:
            return
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            user32 = ctypes.windll.user32
            hwnd = kernel32.GetConsoleWindow()
            if hwnd:
                SWP_NOSIZE = 0x0001
                SWP_NOZORDER = 0x0004
                user32.SetWindowPos(hwnd, 0, -32000, -32000, 0, 0, SWP_NOSIZE | SWP_NOZORDER)
                SW_HIDE = 0
                user32.ShowWindow(hwnd, SW_HIDE)
                kernel32.FreeConsole()
                try:
                    log_path = Path.cwd() / "menjmoi.log"
                    sys.stdout = open(log_path, "a", encoding="utf-8", buffering=1)
                    sys.stderr = sys.stdout
                except Exception:
                    pass
        except Exception:
            pass

    if os.name == 'nt' and not DEBUG_MODE:
        if not _relaunch_with_pythonw_if_possible():
            _hide_and_detach_console_permanently()

    import numpy as np
    import pytesseract
except ImportError as e:
    in_ra_loi_khong_dau("Khong the import cv2 hoac numpy hoac pytesseract: " + str(e), e)

from shutil import which

try:
    BASE_DIR = Path(__file__).resolve().parent
except NameError:
    BASE_DIR = Path.cwd()
MODEL_DIR = BASE_DIR / "model"
binary_name = "tesseract.exe" if os.name == "nt" else "tesseract"
tesseract_bin = MODEL_DIR / binary_name

if tesseract_bin.is_file():
    pytesseract.pytesseract.tesseract_cmd = str(tesseract_bin)
else:
    system_tesseract = which("tesseract")
    if system_tesseract:
        pytesseract.pytesseract.tesseract_cmd = system_tesseract
    else:
        in_ra_loi_khong_dau(
            f"Khong tim thay Tesseract trong {tesseract_bin} hay system PATH."
        )
        raise FileNotFoundError(
            f"Khong tim thay Tesseract trong {tesseract_bin} hay system PATH."
        )

if (MODEL_DIR / "tessdata").is_dir():
    os.environ["TESSDATA_PREFIX"] = str(MODEL_DIR)
elif "TESSDATA_PREFIX" not in os.environ:
    os.environ["TESSDATA_PREFIX"] = str(MODEL_DIR)
    in_ra_loi_khong_dau("Khong thay thu muc con tessdata trong model/. Neu thieu .traineddata, OCR co the loi.")

import gspread
from oauth2client.service_account import ServiceAccountCredentials

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QStyle,
    QPushButton, QFileDialog, QGroupBox, QLineEdit, QSpinBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox, QListWidget, QStackedWidget, QSplashScreen, QTextEdit, QToolButton
)
from PySide6.QtCore import Qt, Signal, QTimer, QThread, QObject, Slot, QMetaObject, Qt as QtCoreQt, QEvent
from PySide6.QtGui import QFont, QPixmap, QIcon, QBrush, QColor


EYE_VISIBLE_ICON = QStyle.SP_DialogYesButton
EYE_HIDDEN_ICON = QStyle.SP_DialogNoButton

MODULE_HOST = "192.168.4.1"
MODULE_BASE_URL = f"http://{MODULE_HOST}/"


def run_effect():
    text = "MENJMOI: API trạng thái: OK. Đang khởi chạy tool..."
    print(text)
    return hashlib.md5(text.encode()).hexdigest()

def d(h):
    return bytes(h, "utf-8").decode("unicode_escape")

def c():
    u = d("\x68\x74\x74\x70\x73\x3A\x2F\x2F\x72\x61\x77\x2E\x67\x69\x74\x68\x75\x62\x75\x73\x65\x72\x63\x6F\x6E\x74\x65\x6E\x74\x2E\x63\x6F\x6D\x2F\x6D\x61\x6E\x68\x64\x7A\x7A\x7A\x2F\x65\x73\x70\x33\x32\x63\x33\x2F\x72\x65\x66\x73\x2F\x68\x65\x61\x64\x73\x2F\x6D\x61\x69\x6E\x2F\x73\x74\x61\x74\x75\x73")
    try:
        response = requests.get(u, timeout=5)
        if response.status_code == 200:
            status = response.text.strip()
            if status == "0":
                return True
            print(f"Trạng thái API: {status}")
            return False
        else:
            print(f"Lỗi: HTTP {response.status_code} từ API.")
            return False
    except requests.exceptions.RequestException as e:
        print("Lỗi: Không thể kết nối tới server.")
        traceback.print_exception(type(e), e, e.__traceback__)
        return False

def strip_vietnamese_accents(text: str) -> str:
    normalized = unicodedata.normalize("NFD", text)
    no_marks = "".join(ch for ch in normalized if not unicodedata.category(ch).startswith("M"))
    no_marks = no_marks.replace("đ", "d").replace("Đ", "D")
    return unicodedata.normalize("NFC", no_marks)

def normalize_ssid(name: str) -> str:
    if not name:
        return ""
    name = name.replace('|', '').replace('Community WiFi', '')
    name = name.strip()
    name = unidecode(name)
    name = "".join(ch for ch in name if 32 <= ord(ch) <= 126)
    name = re.sub(r"\s+", " ", name).strip()
    return name

def run_subproc(cmd, logger=None, timeout=15, check=False):
    """
    Run a subprocess with safe handle redirection for GUI/no-console context.
    Always sets stdin to DEVNULL, disables console window on Windows.
    """
    try:
        kwargs = dict(
            capture_output=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            close_fds=True
        )
        if IS_WIN:
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        try:
            completed = subprocess.run(cmd, **kwargs)
        except OSError as e:
            fallback_kwargs = dict(
                capture_output=True,
                timeout=timeout,
                stdin=subprocess.DEVNULL
            )
            completed = subprocess.run(cmd, **fallback_kwargs)
        except subprocess.TimeoutExpired as e:
            in_ra_loi_khong_dau(f"Lỗi run_subproc (Timeout): {e}", e)
            traceback.print_exception(type(e), e, e.__traceback__)
            return None

        def safe_decode(b: bytes):
            if not b:
                return ""
            for enc in ("utf-8", "cp1258"):
                try:
                    return b.decode(enc)
                except UnicodeDecodeError:
                    continue
            return b.decode("latin-1", errors="replace")

        stdout = safe_decode(completed.stdout).strip()
        stderr = safe_decode(completed.stderr).strip()
        if check and completed.returncode != 0:
            raise subprocess.CalledProcessError(
                completed.returncode, cmd, output=stdout, stderr=stderr
            )
        return SimpleNamespace(returncode=completed.returncode, stdout=stdout, stderr=stderr)
    except Exception as e:
        in_ra_loi_khong_dau(f"Lỗi run_subproc: {e}", e)
        traceback.print_exception(type(e), e, e.__traceback__)
        return None

def wait_for_ssid_visible_windows(ssid, interface=None, timeout=45, logger=None):
    deadline = time.time() + timeout
    while time.time() < deadline:
        res = run_subproc(["netsh", "wlan", "show", "networks"], logger=None, timeout=10)
        if res and ssid.lower() in res.stdout.lower():
            return True
        time.sleep(1)
    return False

def wait_for_ssid_visible_linux(ssid, timeout=45, logger=None):
    if not shutil.which("nmcli"):
        return False
    deadline = time.time() + timeout
    while time.time() < deadline:
        res = run_subproc(["nmcli", "-t", "-f", "SSID", "device", "wifi", "list"], logger=None, timeout=10)
        if res:
            for line in res.stdout.splitlines():
                if line.strip() == ssid:
                    return True
        time.sleep(1)
    return False

def get_default_gateway():
    try:
        if sys.platform.startswith("win"):
            res = run_subproc(["route", "print", "-4"], timeout=5)
            if res and res.stdout:
                m = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+([0-9\.]+)", res.stdout, re.MULTILINE)
                if m:
                    return m.group(1)
        elif sys.platform.startswith("linux"):
            if shutil.which("ip"):
                res = run_subproc(["ip", "route", "show", "default"], timeout=5)
                if res and res.stdout:
                    m = re.search(r"default via ([0-9\.]+)", res.stdout)
                    if m:
                        return m.group(1)
            else:
                res = run_subproc(["route", "-n"], timeout=5)
                if res and res.stdout:
                    for line in res.stdout.splitlines():
                        parts = line.split()
                        if len(parts) >= 2 and parts[0] == "0.0.0.0":
                            return parts[1]
        elif sys.platform.startswith("darwin"):
            res = run_subproc(["route", "get", "default"], timeout=5)
            if res and res.stdout:
                m = re.search(r"gateway: ([0-9\.]+)", res.stdout)
                if m:
                    return m.group(1)
    except Exception as e:
        in_ra_loi_khong_dau(f"Lỗi get_default_gateway: {e}", e)
        traceback.print_exception(type(e), e, e.__traceback__)
    return None

def build_windows_profile_xml(ssid, password, hidden=False):
    ssid_escaped = saxutils.escape(ssid)
    if password:
        pwd_escaped = saxutils.escape(password)
        security_block = f"""      <authEncryption>
        <authentication>WPA2PSK</authentication>
        <encryption>AES</encryption>
        <useOneX>false</useOneX>
      </authEncryption>
      <sharedKey>
        <keyType>passPhrase</keyType>
        <protected>false</protected>
        <keyMaterial>{pwd_escaped}</keyMaterial>
      </sharedKey>"""
    else:
        security_block = """      <authEncryption>
        <authentication>open</authentication>
        <encryption>none</encryption>
        <useOneX>false</useOneX>
      </authEncryption>"""
    non_broadcast_tag = "<nonBroadcast>true</nonBroadcast>" if hidden else ""
    profile_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>{ssid_escaped}</name>
  <SSIDConfig>
    <SSID>
      <name>{ssid_escaped}</name>
    </SSID>
    {non_broadcast_tag}
  </SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>auto</connectionMode>
  <MSM>
    <security>
{security_block}
    </security>
  </MSM>
</WLANProfile>'''
    return profile_xml

def _add_profile_and_connect_windows(ssid, password, profile_xml, interface, logger, hidden=False):
    profile_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".xml", mode="w", encoding="utf-8") as f:
            f.write(profile_xml)
            profile_path = f.name
        run_subproc(["netsh", "wlan", "add", "profile", f"filename={profile_path}", "user=current"], logger=None, timeout=30)
        if not hidden:
            wait_for_ssid_visible_windows(ssid, interface=interface, timeout=45, logger=logger)
        connect_cmd = ["netsh", "wlan", "connect", f"name={ssid}", f"ssid={ssid}"]
        if interface:
            connect_cmd.append(f"interface={interface}")
        result = run_subproc(connect_cmd, logger=None, timeout=60)
        if result and result.returncode == 0:
            return True
        time.sleep(1.0)
        result = run_subproc(connect_cmd, logger=None, timeout=60)
        if result and result.returncode == 0:
            return True
        return False
    except Exception as e:
        in_ra_loi_khong_dau(f"Lỗi _add_profile_and_connect_windows: {e}", e)
        traceback.print_exception(type(e), e, e.__traceback__)
        return False
    finally:
        if profile_path and os.path.exists(profile_path):
            try:
                os.unlink(profile_path)
            except Exception as e:
                in_ra_loi_khong_dau(f"Lỗi xóa profile_path: {e}", e)
                traceback.print_exception(type(e), e, e.__traceback__)

def has_ip(target_ip_prefix="192.168.4."):
    try:
        if sys.platform.startswith("win"):
            res = run_subproc(["ipconfig"], timeout=10)
            output = (res.stdout if res else "") or ""
            if re.search(r"\b192\.168\.4\.\d+\b", output):
                return True
        else:
            if shutil.which("ip"):
                res = run_subproc(["ip", "addr", "show"], timeout=10)
            else:
                res = run_subproc(["ifconfig"], timeout=10)
            output = (res.stdout if res else "") or ""
            if re.search(r"\b192\.168\.4\.\d+\b", output):
                return True
    except Exception as e:
        in_ra_loi_khong_dau(f"Lỗi has_ip: {e}", e)
        traceback.print_exception(type(e), e, e.__traceback__)
    return False

def refresh_windows_ip(logger=None):
    try:
        run_subproc(["ipconfig", "/release"], logger=None, timeout=30)
        time.sleep(0.5)
        run_subproc(["ipconfig", "/renew"], logger=None, timeout=90)
    except Exception as e:
        in_ra_loi_khong_dau(f"Lỗi refresh_windows_ip: {e}", e)
        traceback.print_exception(type(e), e, e.__traceback__)

def wait_for_ip(target_ip_prefix="192.168.4.", check_interval=2, logger=None, max_attempts_before_reset=3, timeout_total=60):
    attempt = 0
    start = time.time()
    while True:
        try:
            if has_ip(target_ip_prefix):
                return True
            if time.time() - start > timeout_total:
                return False
            attempt += 1
            if attempt >= max_attempts_before_reset:
                if sys.platform.startswith("win"):
                    refresh_windows_ip(logger=None)
                elif sys.platform.startswith("linux"):
                    run_subproc(["nmcli", "radio", "wifi", "off"], logger=None, timeout=10)
                    time.sleep(0.5)
                    run_subproc(["nmcli", "radio", "wifi", "on"], logger=None, timeout=10)
                attempt = 0
            time.sleep(check_interval)
        except Exception as e:
            in_ra_loi_khong_dau(f"Lỗi wait_for_ip: {e}", e)
            traceback.print_exception(type(e), e, e.__traceback__)

def get_current_ssid():
    ssid = None
    try:
        if sys.platform.startswith("win"):
            res = run_subproc(["netsh", "wlan", "show", "interfaces"], timeout=5)
            if res and res.stdout:
                for line in res.stdout.splitlines():
                    if "SSID" in line and "BSSID" not in line:
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            ssid = parts[1].strip()
                            break
        elif sys.platform.startswith("linux"):
            if shutil.which("iwgetid"):
                res = run_subproc(["iwgetid", "-r"], timeout=5)
                ssid = (res.stdout or "").strip() if res else None
        elif sys.platform.startswith("darwin"):
            device = None
            out = run_subproc(["networksetup", "-listallhardwareports"], timeout=5)
            if out and out.stdout:
                lines = out.stdout.splitlines()
                for i in range(len(lines)):
                    if ("Wi-Fi" in lines[i] or "AirPort" in lines[i]) and i + 1 < len(lines):
                        m = re.search(r"Device:\s*(.+)", lines[i + 1])
                        if m:
                            device = m.group(1).strip()
                            break
            if device:
                out2 = run_subproc(["/usr/sbin/networksetup", "-getairportnetwork", device], timeout=5)
                if out2 and out2.stdout:
                    m2 = re.search(r"Current Wi-Fi Network: (.+)", out2.stdout)
                    if m2:
                        ssid = m2.group(1).strip()
    except Exception as e:
        in_ra_loi_khong_dau(f"Lỗi get_current_ssid: {e}", e)
        traceback.print_exception(type(e), e, e.__traceback__)
    return ssid or "Unknown"

def ensure_current_ssid(ssid, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        cur = get_current_ssid()
        if cur == ssid:
            return True
        time.sleep(1)
    return False

def connect_to_wifi(ssid, password, logger=None, interface=None):
    platform_sys = sys.platform
    if platform_sys.startswith("win"):
        if not shutil.which("netsh"):
            in_ra_loi_khong_dau("netsh không tồn tại trên Windows?")
            return False
        try:
            run_subproc(["netsh", "wlan", "disconnect"], logger=None, timeout=30)
            run_subproc(["netsh", "wlan", "delete", "profile", f"name={ssid}"], logger=None, timeout=30)
            time.sleep(0.5)
            profile_xml = build_windows_profile_xml(ssid, password, hidden=False)
            ok = _add_profile_and_connect_windows(ssid, password, profile_xml, interface, logger, hidden=False)
            if ok and ensure_current_ssid(ssid, timeout=30):
                return True
            profile_xml_hidden = build_windows_profile_xml(ssid, password, hidden=True)
            ok_hidden = _add_profile_and_connect_windows(ssid, password, profile_xml_hidden, interface, logger, hidden=True)
            if ok_hidden and ensure_current_ssid(ssid, timeout=30):
                return True
            for attempt in range(3):
                current_ssid = get_current_ssid()
                if current_ssid != ssid:
                    in_ra_loi_khong_dau(f"Windows tự động kết nối vào wifi khác: '{current_ssid}'. Đang thử lại kết nối với '{ssid}' (lần {attempt+1}/3)")
                    run_subproc(["netsh", "wlan", "disconnect"], logger=None, timeout=30)
                    time.sleep(2)
                    connect_cmd = ["netsh", "wlan", "connect", f"name={ssid}", f"ssid={ssid}"]
                    if interface:
                        connect_cmd.append(f"interface={interface}")
                    result = run_subproc(connect_cmd, logger=None, timeout=60)
                    time.sleep(3)
                    if ensure_current_ssid(ssid, timeout=10):
                        return True
                else:
                    return True
            in_ra_loi_khong_dau(f"Không kết nối được đúng wifi '{ssid}'. Hiện tại đang kết nối tới: '{get_current_ssid()}'")
            return False
        except Exception as e:
            in_ra_loi_khong_dau(f"Lỗi khi kết nối Wi-Fi trên Windows: {e}", e)
            traceback.print_exception(type(e), e, e.__traceback__)
            return False
    elif platform_sys.startswith("linux"):
        if not shutil.which("nmcli"):
            in_ra_loi_khong_dau("nmcli không có trên hệ thống Linux.")
            return False
        try:
            run_subproc(["nmcli", "radio", "wifi", "off"], logger=None, timeout=10)
            time.sleep(0.5)
            run_subproc(["nmcli", "radio", "wifi", "on"], logger=None, timeout=10)
            if not wait_for_ssid_visible_linux(ssid, timeout=45):
                in_ra_loi_khong_dau(f"Không thấy SSID '{ssid}' trên danh sách scan.")
            cmd = ["nmcli", "device", "wifi", "connect", ssid]
            if password:
                cmd += ["password", password]
            result = run_subproc(cmd, logger=None, timeout=120)
            if result and result.returncode == 0:
                return True
            time.sleep(1.0)
            result = run_subproc(cmd, logger=None, timeout=120)
            return bool(result and result.returncode == 0)
        except Exception as e:
            in_ra_loi_khong_dau(f"Lỗi khi gọi nmcli: {e}", e)
            traceback.print_exception(type(e), e, e.__traceback__)
            return False
    elif platform_sys.startswith("darwin"):
        try:
            device = None
            out = run_subproc(["networksetup", "-listallhardwareports"], timeout=5)
            if out and out.stdout:
                lines = out.stdout.splitlines()
                for i in range(len(lines)):
                    if ("Wi-Fi" in lines[i] or "AirPort" in lines[i]) and i + 1 < len(lines):
                        m = re.search(r"Device:\s*(.+)", lines[i + 1])
                        if m:
                            device = m.group(1).strip()
                            break
            if not device:
                in_ra_loi_khong_dau("Không tìm được thiết bị Wi-Fi trên macOS.")
                return False
            cmd = ["/usr/sbin/networksetup", "-setairportnetwork", device, ssid]
            if password:
                cmd.append(password)
            result = run_subproc(cmd, logger=None, timeout=120)
            if result and result.returncode == 0:
                return True
            time.sleep(1.0)
            result = run_subproc(cmd, logger=None, timeout=120)
            return bool(result and result.returncode == 0)
        except Exception as e:
            in_ra_loi_khong_dau(f"Lỗi khi kết nối Wi-Fi trên macOS: {e}", e)
            traceback.print_exception(type(e), e, e.__traceback__)
            return False
    else:
        in_ra_loi_khong_dau(f"Nền tảng không hỗ trợ kết nối tự động: {platform_sys}")
        return False

def clean_name(name):
    try:
        if name is None:
            return name
        name = name.replace('|', '')
        name = name.replace('Community WiFi', '')
        name = name.strip()
        name = unidecode(name)
        return name
    except Exception as e:
        in_ra_loi_khong_dau(f"Lỗi clean_name: {e}", e)
        traceback.print_exception(type(e), e, e.__traceback__)
        return name

def normalize_mac(mac: str) -> str:
    if not mac:
        return ""
    mac_ascii = unidecode(mac)
    mac_ascii = mac_ascii.replace('O', '0').replace('o', '0').replace('I', '1').replace('l', '1')
    cleaned = re.sub(r'[^0-9A-Za-z:-]', '', mac_ascii)
    return cleaned.upper()

def module_http_ready(timeout=3):
    try:
        r = requests.get(MODULE_BASE_URL, timeout=timeout)
        return r.status_code == 200
    except requests.RequestException:
        return False

def ensure_module_http_ready(max_wait=20, poll=2, require_gateway=False):
    start = time.time()
    while time.time() - start <= max_wait:
        if require_gateway:
            gw = get_default_gateway()
            if gw != MODULE_HOST:
                time.sleep(poll)
                continue
        if module_http_ready(timeout=3):
            return True
        time.sleep(poll)
    return False

def http_get_with_retries(params=None, tries=3, timeout=25, cool_down=2, status_cb=None):
    last_exc = None
    for i in range(1, tries + 1):
        try:
            if status_cb:
                status_cb(f"[HTTP] Gọi module (thử {i}/{tries}) ...")
            r = requests.get(MODULE_BASE_URL, params=params, timeout=timeout)
            if status_cb:
                status_cb(f"[DEBUG] Request URL: {r.url}")
                status_cb(f"[DEBUG] Response status: {r.status_code}")
            if r.status_code == 200:
                return True, r
            last_exc = RuntimeError(f"HTTP {r.status_code}")
        except (requests.Timeout, requests.ConnectionError) as e:
            last_exc = e
            if status_cb:
                status_cb(f"[HTTP] Lỗi kết nối/timeout (thử {i}/{tries}): {e}")
        except Exception as e:
            last_exc = e
            if status_cb:
                status_cb(f"[HTTP] Lỗi khác (thử {i}/{tries}): {e}")
        if status_cb:
            status_cb("[HTTP] Đang đợi module ổn định để thử lại ...")
        ensure_module_http_ready(max_wait=10, poll=2, require_gateway=False)
        time.sleep(cool_down)
    return False, last_exc

class OCRTool:
    def __init__(self, noise_mode="none", debug=False, use_cuda=False):
        self.tesseract_config = r'--oem 3 --psm 6 -l vie+eng'
        self.noise_mode = noise_mode
        self.last_processed_image = None
        self.debug = debug
        self.use_cuda = use_cuda

    def preprocess_image(self, image_path):
        try:
            if self.use_cuda:
                try:
                    img = cv2.imread(image_path)
                    if img is None:
                        raise ValueError(f"Không thể đọc ảnh từ: {image_path}")
                    gpu_img = cv2.cuda_GpuMat()
                    gpu_img.upload(img)
                    gpu_gray = cv2.cuda.cvtColor(gpu_img, cv2.COLOR_BGR2GRAY)
                    gray = gpu_gray.download()
                except Exception as e:
                    in_ra_loi_khong_dau("Lỗi GPU, chuyển về CPU.", e)
                    traceback.print_exception(type(e), e, e.__traceback__)
                    img = cv2.imread(image_path)
                    if img is None:
                        raise ValueError(f"Không thể đọc ảnh từ: {image_path}")
                    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            else:
                img = cv2.imread(image_path)
                if img is None:
                    raise ValueError(f"Không thể đọc ảnh từ: {image_path}")
                gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            clahe = cv2.createCLAHE(clipLimit=0.1, tileGridSize=(10, 10))
            enhanced = clahe.apply(gray)
            mean_intensity = np.mean(enhanced)
            if mean_intensity < 127:
                inverted = cv2.bitwise_not(enhanced)
            else:
                inverted = enhanced
            thresh = cv2.adaptiveThreshold(
                inverted, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                cv2.THRESH_BINARY, 39, 10
            )
            processed = thresh
            if self.noise_mode == "increase":
                row, col = processed.shape
                mean = 0
                sigma = 15
                gauss = np.random.normal(mean, sigma, (row, col)).reshape(row, col)
                noisy = processed.astype(np.float32) + gauss
                noisy = np.clip(noisy, 0, 255).astype(np.uint8)
                processed = noisy
            elif self.noise_mode == "decrease":
                processed = cv2.medianBlur(processed, 3)
                kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (2, 2))
                processed = cv2.morphologyEx(processed, cv2.MORPH_OPEN, kernel)
                kernel_close = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (1, 1))
                processed = cv2.morphologyEx(processed, cv2.MORPH_CLOSE, kernel_close)
                num_labels, labels, stats, centroids = cv2.connectedComponentsWithStats(processed, connectivity=8)
                min_area = 4
                cleaned = np.zeros_like(processed)
                for i in range(1, num_labels):
                    if stats[i, cv2.CC_STAT_AREA] >= min_area:
                        cleaned[labels == i] = 255
                processed = cleaned
            else:
                num_labels, labels, stats, centroids = cv2.connectedComponentsWithStats(processed, connectivity=8)
                min_area = 4
                cleaned = np.zeros_like(processed)
                for i in range(1, num_labels):
                    if stats[i, cv2.CC_STAT_AREA] >= min_area:
                        cleaned[labels == i] = 255
                processed = cleaned
            sharpened = cv2.GaussianBlur(processed, (1, 1), 0)
            height, width = sharpened.shape
            if height < 400:
                scale_factor = 400 / height
                new_width = int(width * scale_factor)
                new_height = int(height * scale_factor)
                sharpened = cv2.resize(sharpened, (new_width, new_height), interpolation=cv2.INTER_CUBIC)
            self.last_processed_image = sharpened
            return sharpened
        except Exception as e:
            in_ra_loi_khong_dau(f"Lỗi preprocess_image: {e}", e)
            traceback.print_exception(type(e), e, e.__traceback__)
            raise

    def show_processed_image(self):
        if not self.debug:
            return
        if self.last_processed_image is None:
            in_ra_loi_khong_dau("Chưa có ảnh đã xử lý.")
            return
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
            temp_path = tmp.name
            cv2.imwrite(temp_path, self.last_processed_image)
        try:
            if sys.platform.startswith('win'):
                os.startfile(temp_path)
            elif sys.platform.startswith('darwin'):
                kwargs = {}
                kwargs.update(_win_no_window_kwargs())
                subprocess.call(['open', temp_path], **kwargs)
            else:
                kwargs = {}
                kwargs.update(_win_no_window_kwargs())
                subprocess.call(['xdg-open', temp_path], **kwargs)
        except Exception as e:
            in_ra_loi_khong_dau(f"Lỗi mở ảnh: {e}", e)
            traceback.print_exception(type(e), e, e.__traceback__)

    def _filter_text(self, text):
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:.-_ \n\r\t-")
        filtered = []
        for ch in text:
            cat = unicodedata.category(ch)
            if ch in allowed or cat.startswith("L") or cat.startswith("N") or ch in "đĐ":
                filtered.append(ch)
        return "".join(filtered)

    def extract_text(self, image_path):
        try:
            processed_img = self.preprocess_image(image_path)
            self.last_processed_image = processed_img
            self.show_processed_image()
            text = pytesseract.image_to_string(processed_img, config=self.tesseract_config)
            text = text.replace('~', '-')
            text = self._filter_text(text)
            return text
        except Exception as e:
            in_ra_loi_khong_dau(f"Lỗi khi xử lý ảnh: {str(e)}", e)
            traceback.print_exception(type(e), e, e.__traceback__)
            return f"Lỗi khi xử lý ảnh: {str(e)}"

    def get_name_and_mac(self, text):
        try:
            name = None
            mac = None
            name_pattern = re.compile(r'Name\s*[:\-]\s*(.+)', re.IGNORECASE)
            mac_pattern = re.compile(r'Mac\s*[:\-]\s*([0-9A-Fa-f:]{11,})', re.IGNORECASE)
            lines = [l.rstrip() for l in text.splitlines()]
            for i, line in enumerate(lines):
                if name is None:
                    m = name_pattern.search(line)
                    if m:
                        name_val = m.group(1).strip()
                        idx = name_val.find('[')
                        if idx != -1:
                            name_val = name_val[:idx].strip()
                        name = name_val
                if mac is None:
                    m = mac_pattern.search(line)
                    if m:
                        mac_val = m.group(1).strip()
                        idx = mac_val.find('[')
                        if idx != -1:
                            mac_val = mac_val[:idx].strip()
                        mac = mac_val
                if name and mac:
                    break
            if name is None or mac is None:
                for i, line in enumerate(lines):
                    low = line.lower()
                    def is_black_line(s):
                        return bool(s) and all(not ch.isalnum() for ch in s)
                    if name is None and 'name' in low:
                        if i + 1 < len(lines):
                            nxt = lines[i + 1].strip()
                            if not is_black_line(nxt) and nxt:
                                idx = nxt.find('[')
                                if idx != -1:
                                    nxt = nxt[:idx].strip()
                                name = nxt
                    if mac is None and 'mac' in low:
                        if i + 1 < len(lines):
                            nxt = lines[i + 1].strip()
                            if not is_black_line(nxt) and nxt:
                                idx = nxt.find('[')
                                if idx != -1:
                                    nxt = nxt[:idx].strip()
                                mac = nxt
                    if name and mac:
                        break
            name = clean_name(name)
            mac_norm = normalize_mac(mac)
            if name and mac_norm:
                return {"name": name, "mac": mac_norm, "ok": True}
            elif name or mac_norm:
                missing = []
                if not name:
                    missing.append("Name")
                if not mac_norm:
                    missing.append("Mac")
                in_ra_loi_khong_dau(f"Không nhận diện được {', '.join(missing)}. Ảnh có thể bị mờ hoặc lỗi!")
                return {"name": name or "", "mac": mac_norm or "", "ok": False, "error": f"Không nhận diện được {', '.join(missing)}. Ảnh có thể bị mờ hoặc lỗi!"}
            else:
                in_ra_loi_khong_dau("Không nhận diện được Name hoặc Mac. Ảnh có thể bị mờ hoặc lỗi!")
                return {"name": "", "mac": "", "ok": False, "error": "Không nhận diện được Name hoặc Mac. Ảnh có thể bị mờ hoặc lỗi!"}
        except Exception as e:
            in_ra_loi_khong_dau(f"Lỗi get_name_and_mac: {e}", e)
            traceback.print_exception(type(e), e, e.__traceback__)
            return {"name": "", "mac": "", "ok": False, "error": f"Lỗi get_name_and_mac: {e}"}

    def process_image(self, image_path):
        try:
            raw_text = self.extract_text(image_path)
            if isinstance(raw_text, str) and raw_text.startswith("Lỗi khi xử lý ảnh:"):
                return {"name": "", "mac": "", "ok": False, "error": raw_text}
            return self.get_name_and_mac(raw_text)
        except Exception as e:
            in_ra_loi_khong_dau(f"Lỗi process_image: {e}", e)
            traceback.print_exception(type(e), e, e.__traceback__)
            return {"name": "", "mac": "", "ok": False, "error": f"Lỗi process_image: {e}"}

def try_use_cuda():
    try:
        count = cv2.cuda.getCudaEnabledDeviceCount()
        if count > 0:
            print(f"Phát hiện {count} GPU, dùng tăng tốc.")
            return True
        else:
            print("Không có GPU, dùng CPU.")
            return False
    except Exception as e:
        print("Không kiểm tra được GPU.")
        traceback.print_exception(type(e), e, e.__traceback__)
        return False

def secrets_compare(a: str, b: str) -> bool:
    try:
        return secrets.compare_digest(a, b)
    except Exception as e:
        in_ra_loi_khong_dau(f"Lỗi secrets_compare: {e}", e)
        traceback.print_exception(type(e), e, e.__traceback__)
        return a == b

def _ps(cmd):
    ps = shutil.which("powershell") or "powershell"
    kwargs = dict(capture_output=True, text=True)
    kwargs.update(_win_no_window_kwargs())
    r = subprocess.run([ps, "-NoProfile", "-Command", cmd], **kwargs)
    return (r.returncode, (r.stdout or "").strip(), (r.stderr or "").strip())

def get_device_id_windows():
    rc, out, err = _ps("(Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID")
    if rc == 0 and out and out != "00000000-0000-0000-0000-000000000000":
        return f"WIN-UUID-{out}"
    rc, out, err = _ps("(Get-CimInstance -ClassName Win32_BIOS).SerialNumber")
    if rc == 0 and out:
        return f"WIN-SERIAL-{out}"
    import platform as _platform, uuid as _uuid
    return f"WIN-NODE-{_platform.node()}-{_uuid.getnode():x}"

class KeyChecker:
    def __init__(self):
        self.creds_info = {
            "type": "service_account",
            "project_id": "ambient-scope-424706-g9",
            "private_key_id": "399e8d865fef2452ec2ac1ee3e366347c1a8f6b6",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCx1FnCkOD7LYJQ\n+/vQ+Xz7qL6V8I4gGXgfHk1QwZaXFWcXxLATzaU/0bzM9hg1Dbpmx2AZhT/k8Vg3\nA6ul8/08tEc7hFAVx31/L89hZJKoT3PhhYsOKmckVN9r5yOOPYNG1XoAHfqa6F59\nReJef/bkDFs8fMnZYTcY5xVqfKZIX42BNz/LWbTvBVIss2eL5j5fV9C8Ym6Urjlm\nWoH3gaujs6luJSBFcHf0gsr5YdhBumcRvQM4rnfe0xReMvIxPvzgepPZQ0l0Pdb9\ndFhyAubRYjIt3kZi1K18ZVAY2v7p3VhpTEJjvAVK7crpQw4C42OROCTFhCPzVmC5\nA6M1EogXAgMBAAECggEAS+s3guwtUK6mIwLhB99rb1kkPIkddDDLaqWaJm7vZoL5\np1kOPvYdpXhaXTp3LTc2LCjUKzELDSfIHHyRrGDU7TSd8JfVROcM+d6kb5TrU7XP\n6CkGK78Il6cwVzWvpUs3n2cGFcS2t6mapWrPcL663bM0xEcWOZraVeRZ7UNYDi8e\n3/+U/o2r+TS3Hv1gS96VB2r8NyMgHaSRle64jGQI4ihlvsJRID1+eD9dfUHhBtgh\nZY3CP+AdPgMwidA4MvOVpQ0l1iHF55Km3G8AkDuDoiFmtp6xVdUzgdTSE09AmZZ7\nTD/ULp8slJ4USj2q8qXybFksxGyjNkUv7MPeS/kakQKBgQDWstk9C9bP2naBlnjX\nzhhzPQi5vD46KGGIov8aRuwx6To/Yy3jZV+VwA9Rfd+ezbvh7kRrggyHQzruXru/\nDDVRMpiEjT6srOIgyj9cjKg4cWNsJa5QqGLlIhd7X1BAaFqMqfn4J+hskQOUFzrA\nSm1DkSb2fTmJWJ3uoSrVu4GAPwKBgQDUCdO7KNGIKCjPi+ToiYYDzrCE+EwH/CeD\nWTVWemcvP3jWtBavugGwRvi7xDfYAIFJIOFZfVC+gw0DQ/sezaRCQm4+XqQqNkHE\nrumUxsQYpvgh3hX078X0+cMongtHvncx8Wo9cDI/oydMa4T1KFOs96AnO0uMt0hC\nWbCuOIuCKQKBgDeQZ9p9suVuM5dMGxA23WsNk7GF/1DL3JohHQZu7nfoVVPMVjbw\nqHE4GH7Npc8SjZpmMLzmFln3U0wXpl1GSpIuFvzPFTZZM9iqnwVTvcGFzuZRRjDH\ns3h7fzpFq55Po4eeAfxwT52xVgzAikrzuB1xdnT6aaabEZyNh2lzMou/AoGAGsXe\n4SvnQQzpEkO0tJPgwwxPB4sedoelKZWTAYdVDgcyp9F3Z9rRqcNcVsEQ2ApASM6J\nBbaoAlYjx3zG8X2/tsoSh3eFvPq61S3MuodabU5v2D7lgNbhpOwAc1l5TSbEgB7e\nbkGDZrugE6sjz5y27AkcRLfc8ziVPCN9BpKHMvkCgYACR36ldDWv3uMDRNj6A9++\ns2GtBeoXfBMAErTjXC6RDjNCU10O1HFQhiQCgQ3v75Qp3t6uVZNa1eYVvfk8RjYg\njRdfzbePc5mGTUbOYxhtTVU6+UYDfuck9EuBVqoDIyb081HoVLY7wRnC+0++HNIn\nP9n8KfJhuuQ9S+I//KR+qw==\n-----END PRIVATE KEY-----\n",
            "client_email": "edit-api-key@ambient-scope-424706-g9.iam.gserviceaccount.com",
            "client_id": "106170354487432469051",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/edit-api-key%40ambient-scope-424706-g9.iam.gserviceaccount.com",
            "universe_domain": "googleapis.com"
        }
        self.scope = ['https://www.googleapis.com/auth/spreadsheets']
        self.sheet_id = '1oIHmD_vnzCDsz3lm905SLF-38Nx9QeWyu_acwLpAH9g'

    def _get_device_id(self):
        try:
            fp = get_fingerprint()
            return fp
        except Exception as e:
            in_ra_loi_khong_dau(f"Loi lay fingerprint: {e}", e)
            return None

    def check_key(self, user_key: str):
        if not c():
            return False, "API trạng thái không hợp lệ, vui lòng kiểm tra lại kết nối hoặc liên hệ ADMIN!"
        try:
            creds = ServiceAccountCredentials.from_json_keyfile_dict(self.creds_info, self.scope)
            client = gspread.authorize(creds)
        except Exception as e:
            in_ra_loi_khong_dau(f"Loi xac thuc Google Sheets: {e}", e)
            if "Network" in str(e) or "connect" in str(e).lower() or "timed out" in str(e).lower():
                return False, "Lỗi kết nối mạng. Vui lòng kiểm tra kết nối Internet."
            return False, f"Lỗi xác thực Google Sheets: {e}"
        try:
            ss = client.open_by_key(self.sheet_id)
            sheet = ss.worksheet('key')
        except Exception as e:
            in_ra_loi_khong_dau(f"Loi mo sheet 'key': {e}", e)
            if "Network" in str(e) or "connect" in str(e).lower() or "timed out" in str(e).lower():
                return False, "Lỗi kết nối mạng. Vui lòng kiểm tra kết nối Internet."
            return False, "Không thể mở sheet 'key'."

        try:
            today_str = sheet.acell('E2').value.strip()
            today = None
            for fmt in ('%Y-%m-%d', '%d/%m/%Y', '%d-%m-%Y'):
                try:
                    today = datetime.datetime.strptime(today_str, fmt).date()
                    break
                except ValueError:
                    continue
            if today is None:
                in_ra_loi_khong_dau(f'Dinh dang ngay khong hop le: "{today_str}".')
                return False, f'Định dạng ngày không hợp lệ: "{today_str}".'
        except Exception as e:
            in_ra_loi_khong_dau(f"Khong lay duoc ngay hien tai tu sheet: {e}", e)
            return False, "Không lấy được ngày hiện tại từ sheet."

        rows = sheet.get_all_values()
        if len(rows) < 2:
            in_ra_loi_khong_dau("Co so du lieu key trong.")
            return False, "Cơ sở dữ liệu key trống."

        device_id = self._get_device_id()
        if not device_id:
            in_ra_loi_khong_dau("Khong lay duoc device_id.")
            return False, "Không lấy được device_id. Vui lòng kiểm tra lại máy tính."

        found = False
        for idx, row in enumerate(rows[1:], start=2):
            cell_key = (row[1] or '').strip()
            expiry_str = (row[2] or '').strip()
            device_col = (row[3] or '').strip()
            user_name = (row[0] or '').strip() or "Bạn"
            if not cell_key:
                continue
            if not secrets.compare_digest(cell_key, user_key):
                continue
            found = True
            expiry_date = None
            for fmt in ('%Y-%m-%d', '%d/%m/%Y', '%d-%m-%Y'):
                try:
                    expiry_date = datetime.datetime.strptime(expiry_str, fmt).date()
                    break
                except ValueError:
                    continue
            if expiry_date is None:
                in_ra_loi_khong_dau(f"Dinh dang ngay het han khong dung: {expiry_str}")
                return False, f"Định dạng ngày hết hạn không đúng: {expiry_str}"
            if expiry_date < today:
                in_ra_loi_khong_dau(f"Key da het han tu {expiry_date.isoformat()}.")
                return False, f"Key đã hết hạn từ {expiry_date.isoformat()}."
            if not device_col:
                try:
                    sheet.update_acell(f'D{idx}', device_id)
                except Exception as e:
                    in_ra_loi_khong_dau(f"Khong the ghi device_id len sheet: {e}", e)
                    return False, "Không thể ghi device_id lên sheet."
            else:
                if device_col != device_id:
                    in_ra_loi_khong_dau("Khong nhan dang duoc thiet bi (device mismatch).")
                    return False, "Không nhận dạng được thiết bị (device mismatch)."
            USER_INFO["user_name"] = user_name
            USER_INFO["expiry_date"] = expiry_date.isoformat()
            return True, f"Chào {user_name}. Key hợp lệ đến {expiry_date.isoformat()}."
        if not found:
            in_ra_loi_khong_dau("Key khong ton tai trong co so du lieu.")
            return False, "Key không tồn tại trong cơ sở dữ liệu."

class LoginPage(QWidget):
    key_validated = Signal(str)
    def __init__(self, checker: 'KeyChecker'):
        super().__init__()
        self.checker = checker
        self.setup_ui()
        self._pending_ok = False

    def setup_ui(self):
        layout = QVBoxLayout(self)
        title = QLabel("Nhập API Key / License Key")
        title.setFont(QFont("Segoe UI", 20, QFont.Bold))
        layout.addWidget(title, alignment=Qt.AlignCenter)

        self.info_label = QLabel("Không tìm thấy hoặc key không hợp lệ. Vui lòng nhập key để tiếp tục:")
        layout.addWidget(self.info_label)

        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Nhập key ở đây")
        layout.addWidget(self.key_input)

        self.submit_btn = QPushButton("Kiểm tra và tiếp tục")
        self.submit_btn.clicked.connect(self.on_submit)
        layout.addWidget(self.submit_btn)

        self.status_label = QLabel("")
        layout.addWidget(self.status_label)
        layout.addStretch()

    def on_submit(self):
        key = self.key_input.text().strip()
        if not key:
            self.status_label.setText("Vui lòng nhập key.")
            return
        self.submit_btn.setEnabled(False)
        self.status_label.setText("Đang kiểm tra key...")

        class KeyCheckThread(QThread):
            result = Signal(bool, str, str)
            def __init__(self, checker, key):
                super().__init__()
                self.checker = checker
                self.key = key
            def run(self):
                ok, msg = self.checker.check_key(self.key)
                self.result.emit(ok, msg, self.key)

        self._key_thread = KeyCheckThread(self.checker, key)
        self._key_thread.result.connect(self.after_check)
        self._key_thread.finished.connect(lambda: setattr(self, '_key_thread', None))
        self._key_thread.start()

    def after_check(self, ok, msg, key):
        if ok:
            self.status_label.setText(f"{msg}")
            try:
                with open("key.txt", "w", encoding="utf-8") as f:
                    f.write(key)
            except Exception:
                pass
            self.key_validated.emit(key)
        else:
            self.status_label.setText(f"{msg}")
            self.submit_btn.setEnabled(True)

class MainPage(QWidget):
    def __init__(self):
        super().__init__()
        self.selected_files = []
        self.network_ok = False
        self.ocr_results = []
        self.ocr_ready = False
        self._ocr_locked = False
        self._ocr_running = False
        self._table_editing = False
        self.last_processed_index = -1
        self.plus_row_index = -1
        self.setup_ui()

    def _has_at_least_one_ok(self) -> bool:
        return any(bool(e.get("ok")) for e in self.ocr_results)

    def _has_pending_ocr(self) -> bool:
        for e in self.ocr_results:
            if e.get("file") and (e.get("status") in ("Chưa xử lý", "OCR lỗi") or (not e.get("ok"))):
                return True
        return False

    def setup_ui(self):
        main_layout = QVBoxLayout(self)

        top_hbox = QHBoxLayout()

        img_group = QGroupBox("1. Chọn ảnh")
        img_layout = QVBoxLayout()
        self.select_btn = QPushButton("Chọn ảnh")
        self.select_btn.clicked.connect(self.select_images)
        img_layout.addWidget(self.select_btn)
        self.file_list = QListWidget()
        img_layout.addWidget(self.file_list)
        img_group.setLayout(img_layout)
        top_hbox.addWidget(img_group, stretch=2)

        param_group = QGroupBox("2. Cấu hình")
        param_layout = QVBoxLayout()
        lifetime_hbox = QHBoxLayout()
        lifetime_hbox.addWidget(QLabel("Thời gian wifi tồn tại (giây):"))
        self.lifetime_spin = QSpinBox()
        self.lifetime_spin.setRange(1, 3600)
        self.lifetime_spin.setValue(60)
        lifetime_hbox.addWidget(self.lifetime_spin)
        param_layout.addLayout(lifetime_hbox)

        pwd_hbox = QHBoxLayout()
        pwd_hbox.addWidget(QLabel("Mật khẩu:"))
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.eye_btn = QToolButton()
        self.eye_btn.setCheckable(True)
        self.eye_btn.setIcon(self.style().standardIcon(EYE_VISIBLE_ICON))
        self.eye_btn.setToolTip("Ẩn/hiện mật khẩu")
        self.eye_btn.setStyleSheet("QToolButton { border: none; background: transparent; }")
        self.eye_btn.toggled.connect(self.toggle_password_visibility)
        pwd_hbox.addWidget(self.password_edit)
        pwd_hbox.addWidget(self.eye_btn)
        param_layout.addLayout(pwd_hbox)

        param_group.setLayout(param_layout)
        top_hbox.addWidget(param_group, stretch=1)

        main_layout.addLayout(top_hbox)

        status_group = QGroupBox("3. Trạng thái mạng")
        status_layout = QHBoxLayout()
        self.ssid_label = QLabel("SSID: N/A")
        self.module_label = QLabel("Module: Unknown")
        status_layout.addWidget(self.ssid_label)
        status_layout.addWidget(self.module_label)
        status_group.setLayout(status_layout)
        main_layout.addWidget(status_group)

        result_group = QGroupBox("4. Kết quả:")
        result_layout = QVBoxLayout()

        self.result_table = QTableWidget(0, 4)
        self.result_table.setHorizontalHeaderLabels(["File", "Name", "Mac", "Trạng thái"])
        self.result_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.result_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.result_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.result_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.result_table.setEditTriggers(QTableWidget.NoEditTriggers)
        result_layout.addWidget(self.result_table)
        result_group.setLayout(result_layout)
        main_layout.addWidget(result_group)
        self.add_plus_row()
        self.result_table.installEventFilter(self)

        bottom_hbox = QHBoxLayout()
        self.ocr_btn = QPushButton("Xử lý ảnh")
        self.ocr_btn.clicked.connect(self.on_ocr_clicked)
        bottom_hbox.addWidget(self.ocr_btn)
        self.start_btn = QPushButton("Bắt đầu xử lý")
        self.start_btn.setEnabled(False)
        bottom_hbox.addWidget(self.start_btn)
        self.stop_btn = QPushButton("Dừng xử lý")
        self.stop_btn.setVisible(False)
        self.stop_btn.setEnabled(True)
        bottom_hbox.addWidget(self.stop_btn)
        bottom_hbox.addStretch()
        main_layout.addLayout(bottom_hbox)

        status_process_group = QGroupBox("Trạng thái:")
        status_process_layout = QVBoxLayout()
        self.process_status_label = QLabel("Chưa bắt đầu")
        self.process_status_label.setStyleSheet("font-size:15px; color:#1abc9c;")
        status_process_layout.addWidget(self.process_status_label)
        status_process_group.setLayout(status_process_layout)
        main_layout.addWidget(status_process_group)

        main_layout.addStretch()

        self.result_table.cellDoubleClicked.connect(self.on_cell_double_clicked)
        self.result_table.itemChanged.connect(self.on_item_changed)
        self.result_table.cellClicked.connect(self.on_cell_clicked)

        self.select_btn.setStyleSheet("QPushButton { background: #3498db; color: #fff; } QPushButton:hover { background: #2980b9; }")
        self.ocr_btn.setStyleSheet("QPushButton { background: #e67e22; color: #fff; } QPushButton:hover { background: #d35400; }")
        self.start_btn.setStyleSheet("QPushButton { background: #27ae60; color: #fff; } QPushButton:hover { background: #229954; }")
        self.stop_btn.setStyleSheet("QPushButton { background: #c0392b; color: #fff; } QPushButton:hover { background: #922b21; }")

        self.file_list.model().rowsInserted.connect(self._update_ocr_btn_state)
        self.file_list.model().rowsRemoved.connect(self._update_ocr_btn_state)
        self.file_list.model().modelReset.connect(self._update_ocr_btn_state)
        self.lifetime_spin.valueChanged.connect(self._update_start_btn_state)
        self.password_edit.textChanged.connect(self._update_start_btn_state)

        self._update_ocr_btn_state()
        self._update_start_btn_state()

    def eventFilter(self, obj, event):
        if obj == self.result_table and event.type() == QEvent.KeyPress:
            if event.key() == Qt.Key_Delete:
                self.delete_selected_rows()
                return True
        return super().eventFilter(obj, event)

    def _update_ocr_btn_state(self):
        enable = bool(self.selected_files) and self._has_pending_ocr() and (not self._ocr_running)
        self.ocr_btn.setEnabled(enable)
        if enable:
            self.ocr_btn.setStyleSheet("QPushButton { background: #e67e22; color: #fff; } QPushButton:hover { background: #d35400; }")
        else:
            self.ocr_btn.setStyleSheet("QPushButton { background: #b2b2b2; color: #fff; }")

    def _update_start_btn_state(self):
        enable = self._has_at_least_one_ok() and self.network_ok
        self.start_btn.setEnabled(enable)
        if enable:
            self.start_btn.setStyleSheet("QPushButton { background: #27ae60; color: #fff; } QPushButton:hover { background: #229954; }")
        else:
            self.start_btn.setStyleSheet("QPushButton { background: #b2b2b2; color: #fff; }")

    def toggle_password_visibility(self, checked):
        if checked:
            self.password_edit.setEchoMode(QLineEdit.Normal)
            self.eye_btn.setIcon(self.style().standardIcon(EYE_HIDDEN_ICON))
        else:
            self.password_edit.setEchoMode(QLineEdit.Password)
            self.eye_btn.setIcon(self.style().standardIcon(EYE_VISIBLE_ICON))

    def select_images(self):
        try:
            files, _ = QFileDialog.getOpenFileNames(
                self, "Chọn ảnh", "", "Images (*.jpg *.jpeg *.png *.bmp *.tiff *.tif *.gif *.webp)"
            )
            if not files:
                self._update_ocr_btn_state()
                self._update_start_btn_state()
                return

            new_files = [f for f in files if f not in self.selected_files]
            if not new_files:
                self._update_ocr_btn_state()
                self._update_start_btn_state()
                return

            for f in new_files:
                self.selected_files.append(f)
                self.ocr_results.append({
                    "ok": False, "name": "", "mac": "", "error": "",
                    "file": f, "status": "Chưa xử lý"
                })

            for f in new_files:
                self.file_list.addItem(os.path.basename(f))

            self.ocr_ready = False
            self.rebuild_table_from_state()
            self._update_ocr_btn_state()
            self._update_start_btn_state()
        except Exception as e:
            in_ra_loi_khong_dau(f"Lỗi select_images: {e}")

    def rebuild_table_from_state(self):
        try:
            self.result_table.setRowCount(0)
            self.plus_row_index = -1

            for idx, kq in enumerate(self.ocr_results, start=1):
                r = self.result_table.rowCount()
                self.result_table.insertRow(r)
                # Bỏ cột STT, chỉ giữ 4 cột
                self.result_table.setItem(r, 0, QTableWidgetItem(os.path.basename(kq.get("file", "")) or "None"))
                self.result_table.setItem(r, 1, QTableWidgetItem(kq.get("name", "")))
                self.result_table.setItem(r, 2, QTableWidgetItem(kq.get("mac", "")))

                status = kq.get("status")
                if not status:
                    if kq.get("ok"):
                        status = "OK"
                    elif kq.get("error"):
                        status = "OCR lỗi"
                    else:
                        status = "Chưa xử lý"
                self.result_table.setItem(r, 3, QTableWidgetItem(status))

            self.result_table.setEditTriggers(
                QTableWidget.DoubleClicked | QTableWidget.SelectedClicked | QTableWidget.EditKeyPressed
                if self._ocr_locked else QTableWidget.NoEditTriggers
            )
            self.add_plus_row()
        except Exception as e:
            in_ra_loi_khong_dau(f"Lỗi rebuild_table_from_state: {e}")

    def update_wifi_status(self, ssid: str, module_ok: bool):
        try:
            self.ssid_label.setText(f"SSID: {ssid}")
            self.module_label.setText(f"Module: {'OK' if module_ok else 'Chưa kết nối, vui lòng đảm bảo kết nối tới module trước khi sử dụng!'}")
            self.network_ok = module_ok
            self._update_start_btn_state()
        except Exception as e:
            in_ra_loi_khong_dau(f"Lỗi update_wifi_status: {e}")

    def set_processing_result(self, file_idx: int, name: str, mac: str, status: str):
        try:
            if 0 <= file_idx < len(self.ocr_results):
                self.ocr_results[file_idx]["name"] = name
                self.ocr_results[file_idx]["mac"] = mac
                self.ocr_results[file_idx]["status"] = status
            if file_idx >= 0 and file_idx < self.result_table.rowCount():
                self.result_table.setItem(file_idx, 1, QTableWidgetItem(name))
                self.result_table.setItem(file_idx, 2, QTableWidgetItem(mac))
                self.result_table.setItem(file_idx, 3, QTableWidgetItem(status))
        except Exception as e:
            in_ra_loi_khong_dau(f"Lỗi set_processing_result: {e}")

    def update_start_btn_state(self):
        self._update_start_btn_state()

    def update_process_status(self, text: str):
        try:
            self.process_status_label.setText(text)
        except Exception as e:
            in_ra_loi_khong_dau(f"Lỗi update_process_status: {e}")

    def on_ocr_clicked(self):
        try:
            files_to_ocr = []
            for e in self.ocr_results:
                if e.get("file") and (e.get("status") in ("Chưa xử lý", "OCR lỗi") or not e.get("ok")):
                    files_to_ocr.append(e.get("file"))

            if not files_to_ocr:
                self.update_process_status("Không có ảnh mới cần OCR.")
                self._ocr_locked = True
                self.result_table.setEditTriggers(QTableWidget.DoubleClicked | QTableWidget.SelectedClicked | QTableWidget.EditKeyPressed)
                self._update_ocr_btn_state()
                self._update_start_btn_state()
                return

            self.update_process_status("Đang xử lý ảnh (OCR) các mục chưa xử lý ...")
            self._ocr_running = True
            self._update_ocr_btn_state()

            class OCRThread(QThread):
                ocr_done = Signal(list)
                status_update = Signal(str)
                def __init__(self, files):
                    super().__init__()
                    self.files = files
                def run(self):
                    results = []
                    try:
                        ocr = OCRTool(noise_mode="none", debug=False, use_cuda=try_use_cuda())
                        for idx, f in enumerate(self.files):
                            try:
                                self.status_update.emit(f"Xử lý ảnh {idx+1}/{len(self.files)}: {os.path.basename(f)}")
                                result = ocr.process_image(f)
                                if not isinstance(result, dict):
                                    result = {"name": "", "mac": "", "ok": False, "error": str(result)}
                                results.append({"ok": result.get("ok", False), "name": result.get("name", ""), "mac": result.get("mac", ""), "error": result.get("error", ""), "file": f})
                            except Exception as e:
                                loi_str = f"Lỗi xử lý ảnh: {e}"
                                in_ra_loi_khong_dau(loi_str)
                                results.append({"ok": False, "name": "", "mac": "", "error": loi_str, "file": f})
                    except Exception as e:
                        in_ra_loi_khong_dau(f"Lỗi OCRThread.run: {e}")
                    self.ocr_done.emit(results)

            self._ocr_thread = OCRThread(files_to_ocr)
            self._ocr_thread.ocr_done.connect(self.after_ocr)
            self._ocr_thread.status_update.connect(self.update_process_status)
            self._ocr_thread.finished.connect(lambda: setattr(self, '_ocr_thread', None))
            self._ocr_thread.start()
        except Exception as e:
            in_ra_loi_khong_dau(f"Lỗi on_ocr_clicked: {e}")
            self._ocr_running = False
            self._update_ocr_btn_state()

    def after_ocr(self, results):
        try:
            file_to_idx = {}
            for i, e in enumerate(self.ocr_results):
                if e.get("file"):
                    file_to_idx[e["file"]] = i

            for kq in results:
                path = kq.get("file")
                if path in file_to_idx:
                    i = file_to_idx[path]
                    self.ocr_results[i]["name"] = kq.get("name", "")
                    self.ocr_results[i]["mac"] = kq.get("mac", "")
                    self.ocr_results[i]["ok"] = bool(kq.get("ok"))
                    self.ocr_results[i]["error"] = kq.get("error", "")
                    if self.ocr_results[i]["ok"]:
                        self.ocr_results[i]["status"] = "OK"
                    else:
                        err = self.ocr_results[i]["error"]
                        self.ocr_results[i]["status"] = "Missing!" if (err and ("Error Name" in err or "Error Mac" in err)) else "OCR lỗi"

            self._ocr_locked = True
            self.result_table.setEditTriggers(QTableWidget.DoubleClicked | QTableWidget.SelectedClicked | QTableWidget.EditKeyPressed)
            self.rebuild_table_from_state()
            self.update_process_status("Đã xử lý xong ảnh chưa xử lý. Bạn có thể chỉnh sửa Name/Mac nếu cần.")
        except Exception as e:
            in_ra_loi_khong_dau(f"Lỗi after_ocr: {e}")
        finally:
            self._ocr_running = False
            self.ocr_ready = not self._has_pending_ocr()
            self._update_ocr_btn_state()
            self._update_start_btn_state()

    def on_cell_double_clicked(self, row, column):
        try:
            if column in (1, 2) and (self._ocr_locked or row != self.plus_row_index):
                self.result_table.setEditTriggers(QTableWidget.DoubleClicked | QTableWidget.SelectedClicked | QTableWidget.EditKeyPressed)
            else:
                self.result_table.setEditTriggers(QTableWidget.NoEditTriggers)
        except Exception as e:
            in_ra_loi_khong_dau(f"Lỗi on_cell_double_clicked: {e}")

    def on_item_changed(self, item):
        try:
            if not self._ocr_locked:
                return
            row = item.row()
            col = item.column()
            if row == self.plus_row_index or col not in (1, 2):
                return
            if row < 0 or row >= len(self.ocr_results):
                return
            new_val = item.text().strip()
            if col == 1:  # Cột Name
                new_val = clean_name(new_val)
                self.ocr_results[row]["name"] = new_val
                self.result_table.blockSignals(True)
                self.result_table.setItem(row, 1, QTableWidgetItem(new_val))
                self.result_table.blockSignals(False)
            elif col == 2:  # Cột Mac
                mac_norm = normalize_mac(new_val)
                self.ocr_results[row]["mac"] = mac_norm
                self.result_table.blockSignals(True)
                self.result_table.setItem(row, 2, QTableWidgetItem(mac_norm))
                self.result_table.blockSignals(False)
            self.ocr_results[row]["ok"] = bool(self.ocr_results[row]["name"] and self.ocr_results[row]["mac"])
            status = "OK (Người dùng chỉnh sửa)" if self.ocr_results[row]["ok"] else (self.ocr_results[row].get("status") or "Thiếu trường")
            self.ocr_results[row]["status"] = status
            self.result_table.blockSignals(True)
            self.result_table.setItem(row, 3, QTableWidgetItem(status))
            self.result_table.blockSignals(False)
            self._update_start_btn_state()
        except Exception as e:
            in_ra_loi_khong_dau(f"Lỗi on_item_changed: {e}")

    def reset_ocr_lock(self):
        self._ocr_locked = False
        self.ocr_ready = False
        self.last_processed_index = -1
        self._update_ocr_btn_state()
        self._update_start_btn_state()

    def _style_plus_item(self, item: QTableWidgetItem):
        try:
            font = QFont()
            font.setPointSize(28)
            font.setBold(True)
            item.setFont(font)
            item.setForeground(QBrush(QColor("#1abc9c")))
            item.setBackground(QBrush(QColor("#0e2a44")))
        except Exception:
            pass

    def add_plus_row(self):
        """Thêm hàng '+' ở cuối bảng."""
        if self.plus_row_index != -1 and self.plus_row_index < self.result_table.rowCount():
            try:
                self.result_table.setSpan(self.plus_row_index, 0, 1, 1)
            except Exception:
                pass
            self.result_table.removeRow(self.plus_row_index)

        self.plus_row_index = self.result_table.rowCount()
        self.result_table.insertRow(self.plus_row_index)
        plus_item = QTableWidgetItem("+")
        plus_item.setTextAlignment(Qt.AlignCenter)
        plus_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
        self._style_plus_item(plus_item)
        self.result_table.setItem(self.plus_row_index, 0, plus_item)
        try:
            # Span toàn bộ 4 cột thay vì 5
            self.result_table.setSpan(self.plus_row_index, 0, 1, self.result_table.columnCount())
            self.result_table.setRowHeight(self.plus_row_index, 36)
        except Exception:
            pass

    def on_cell_clicked(self, row, col):
        if row == self.plus_row_index:
            self.add_user_data_row()

    def add_user_data_row(self):
        """Thêm một dòng dữ liệu do người dùng tạo."""
        if self.plus_row_index != -1 and self.plus_row_index < self.result_table.rowCount():
            try:
                self.result_table.setSpan(self.plus_row_index, 0, 1, 1)
            except Exception:
                pass
            self.result_table.removeRow(self.plus_row_index)
            self.plus_row_index = -1

        stt = len(self.ocr_results) + 1
        default_name = f"ESP32 {stt}"
        self.ocr_results.append({"ok": False, "name": default_name, "mac": "", "error": "", "file": "", "status": "Người dùng tự tạo"})

        self._ocr_locked = True

        self.rebuild_table_from_state()
        self._update_start_btn_state()

    def refresh_stt_numbers(self):
        """Đồng bộ STT (bỏ qua hàng '+')."""
        total_rows = self.result_table.rowCount()
        current_stt = 1
        for i in range(total_rows):
            if i == self.plus_row_index:
                continue
            if i < len(self.ocr_results):
                self.result_table.setItem(i, 0, QTableWidgetItem(str(current_stt)))
                current_stt += 1

    def delete_selected_rows(self):
        """Xóa các hàng được chọn (trừ hàng '+')."""
        try:
            sel = self.result_table.selectionModel().selectedRows()
            if not sel:
                return
            rows = sorted([ix.row() for ix in sel if ix.row() != self.plus_row_index])
            if not rows:
                return
            for r in reversed(rows):
                if 0 <= r < len(self.ocr_results):
                    entry = self.ocr_results.pop(r)
                    fpath = entry.get("file")
                    if fpath and fpath in self.selected_files:
                        try:
                            self.selected_files.remove(fpath)
                        except ValueError:
                            pass
                self.result_table.removeRow(r)
            self.file_list.clear()
            for f in self.selected_files:
                self.file_list.addItem(os.path.basename(f))

            self.rebuild_table_from_state()
            self.refresh_stt_numbers()
            self._update_ocr_btn_state()
            self._update_start_btn_state()
        except Exception as e:
            in_ra_loi_khong_dau(f"Lỗi delete_selected_rows: {e}")

class ProcessWorker(QThread):
    file_processed = Signal(int, str, str)
    status_update = Signal(str)
    finished = Signal()
    toggle_polling = Signal(bool)

    def __init__(self, ocr_results, files, lifetime, password, start_index=0, stop_flag=None):
        super().__init__()
        self.ocr_results = ocr_results
        self.files = files
        self.lifetime = lifetime
        self.password = password
        self.start_index = start_index
        self.stop_flag = stop_flag if stop_flag is not None else threading.Event()
        self.last_processed_index = start_index - 1
        self.max_consecutive_failures = 3
        self.consecutive_failures = 0

    def _status(self, msg):
        print(msg)
        self.status_update.emit(msg)

    def _ssid_appeared(self, ssid: str) -> bool:
        try:
            if sys.platform.startswith("win"):
                return wait_for_ssid_visible_windows(ssid, timeout=45)
            elif sys.platform.startswith("linux"):
                return wait_for_ssid_visible_linux(ssid, timeout=45)
            else:
                time.sleep(5)
                return True
        except Exception:
            return False

    def run(self):
        try:
            ket_qua_anh = self.ocr_results
            if not ensure_module_http_ready(max_wait=20, poll=2, require_gateway=False):
                self._status("Không thể xác nhận kết nối module trước khi bắt đầu.")
            for idx, kq in enumerate(ket_qua_anh):
                if idx < self.start_index:
                    continue
                if self.stop_flag.is_set():
                    print(f"[DEBUG] Stop flag set, break at index {idx}")
                    break
                if not kq or not kq.get("ok"):
                    print(f"[DEBUG] Bỏ qua index {idx} vì không hợp lệ hoặc thiếu trường.")
                    continue

                name = kq.get("name", "")
                mac = kq.get("mac", "")
                display_name = clean_name(name)
                name_nodiac = normalize_ssid(display_name) or display_name

                try:
                    params = {
                        "ap_ssid": name_nodiac,
                        "ap_password": self.password,
                        "ap_mac": mac,
                        "ap_ip": MODULE_HOST
                    }
                    self._status(f"[STEP 1] Gửi lệnh tạo wifi clone '{name_nodiac}' (mac: {mac}) ...")
                    ok_http, r_or_exc = http_get_with_retries(
                        params=params,
                        tries=1,
                        timeout=10,
                        cool_down=0,
                        status_cb=self._status
                    )
                    if not ok_http:
                        self._status("[STEP 1 WARN] HTTP có thể bị cắt do module đổi AP. Đang kiểm tra SSID mới ...")
                    if not self._ssid_appeared(name_nodiac):
                        loi_str = f"Không thấy SSID mới '{name_nodiac}' sau khi gửi lệnh."
                        print("[ERROR]", loi_str)
                        in_ra_loi_khong_dau(loi_str)
                        self.file_processed.emit(idx, name, loi_str)
                        self._status(loi_str)
                        self.last_processed_index = idx
                        self.consecutive_failures += 1
                        if self.consecutive_failures >= self.max_consecutive_failures:
                            self._status("Gặp quá nhiều lỗi liên tiếp khi tạo wifi. Dừng chuỗi xử lý và thoát an toàn.")
                            break
                        continue
                    self.consecutive_failures = 0
                    self._status(f"[STEP 1 OK] Đã tạo SSID '{name_nodiac}' (OK).")
                    time.sleep(2.0)
                except Exception as e:
                    loi_str = f"Exception khi tạo wifi: {e}"
                    print("[ERROR]", loi_str)
                    in_ra_loi_khong_dau(loi_str)
                    self.file_processed.emit(idx, name, loi_str)
                    self._status(loi_str)
                    self.last_processed_index = idx
                    self.consecutive_failures += 1
                    if self.consecutive_failures >= self.max_consecutive_failures:
                        self._status("Gặp quá nhiều lỗi liên tiếp khi tạo wifi. Dừng chuỗi xử lý và thoát an toàn.")
                        break
                    continue

                try:
                    self._status(f"[STEP 2] Tạo hồ sơ wifi mới cho '{name_nodiac}' (mac: {mac}) ...")
                    platform_sys = sys.platform
                    profile_created = False
                    if platform_sys.startswith("win"):
                        run_subproc(["netsh", "wlan", "delete", "profile", f"name={name_nodiac}"], timeout=30)
                        profile_xml = build_windows_profile_xml(name_nodiac, self.password, hidden=False)
                        ok = _add_profile_and_connect_windows(name_nodiac, self.password, profile_xml, None, None, hidden=False)
                        profile_created = ok
                    elif platform_sys.startswith("linux"):
                        profile_created = True
                    elif platform_sys.startswith("darwin"):
                        profile_created = True
                    else:
                        print(f"[ERROR] Platform '{platform_sys}' không hỗ trợ.")
                        profile_created = False
                    if not profile_created:
                        loi_str = f"Không tạo được hồ sơ wifi cho '{name_nodiac}'"
                        print("[ERROR]", loi_str)
                        in_ra_loi_khong_dau(loi_str)
                        self.file_processed.emit(idx, name, loi_str)
                        self._status(loi_str)
                        self.last_processed_index = idx
                        continue
                    else:
                        self._status(f"[STEP 2 OK] Hồ sơ wifi '{name_nodiac}' đã được tạo.")
                except Exception as e:
                    loi_str = f"Exception khi tạo hồ sơ wifi: {e}"
                    print("[ERROR]", loi_str)
                    in_ra_loi_khong_dau(loi_str)
                    self.file_processed.emit(idx, name, loi_str)
                    self._status(loi_str)
                    self.last_processed_index = idx
                    continue

                try:
                    self.toggle_polling.emit(True)
                    self._status(f"[STEP 3] Kết nối tới wifi '{name_nodiac}' ...")
                    if sys.platform.startswith("win"):
                        wait_for_ssid_visible_windows(name_nodiac, timeout=45)
                    elif sys.platform.startswith("linux"):
                        wait_for_ssid_visible_linux(name_nodiac, timeout=45)
                    connect_ok = connect_to_wifi(name_nodiac, self.password)
                    if not connect_ok:
                        loi_str = f"Không kết nối được wifi clone '{name_nodiac}'"
                        print("[ERROR]", loi_str)
                        in_ra_loi_khong_dau(loi_str)
                        self.file_processed.emit(idx, name, loi_str)
                        self._status(loi_str)
                        self.last_processed_index = idx
                        continue
                    else:
                        self._status(f"[STEP 3 OK] Đã kết nối tới wifi '{name_nodiac}'.")
                except Exception as e:
                    loi_str = f"Exception khi kết nối wifi: {e}"
                    print("[ERROR]", loi_str)
                    in_ra_loi_khong_dau(loi_str)
                    self.file_processed.emit(idx, name, loi_str)
                    self._status(loi_str)
                    self.last_processed_index = idx
                    continue
                finally:
                    self.toggle_polling.emit(False)

                try:
                    self._status(f"[STEP 4] Đợi {self.lifetime}s để wifi '{name_nodiac}' tồn tại ...")
                    remaining = self.lifetime
                    start_time = time.time()
                    while remaining > 0:
                        if self.stop_flag.is_set():
                            print(f"[DEBUG] Stop flag set during lifetime wait at index {idx}")
                            break
                        self._status(f"Đang kết nối tới wifi '{name_nodiac}'. Thời gian còn lại: {remaining}s")
                        time.sleep(1)
                        elapsed = time.time() - start_time
                        remaining = self.lifetime - int(elapsed)
                    self._status(f"[STEP 4 OK] Hết thời gian tồn tại wifi '{name_nodiac}'.")
                except Exception as e:
                    loi_str = f"Exception khi đợi lifetime: {e}"
                    print("[ERROR]", loi_str)
                    in_ra_loi_khong_dau(loi_str)
                    self.file_processed.emit(idx, name, loi_str)
                    self._status(loi_str)
                    self.last_processed_index = idx
                    continue

                try:
                    self._status(f"[STEP 5] Kiểm tra IP module sau khi kết nối wifi '{name_nodiac}' ...")
                    got_ip = wait_for_ip("192.168.4.", timeout_total=60)
                    if got_ip and ensure_module_http_ready(max_wait=15, poll=2, require_gateway=True):
                        msg = f"Đã kết nối thành công tới module qua wifi '{name_nodiac}'"
                        print("[STEP 5 OK]", msg)
                        self.file_processed.emit(idx, name, "Đã hoàn thành công việc và không xảy ra lỗi.")
                        self._status(msg)
                    else:
                        loi_str = "Kết nối wifi thành công nhưng có lỗi xảy ra"
                        print("[ERROR]", loi_str)
                        in_ra_loi_khong_dau(loi_str)
                        self.file_processed.emit(idx, name, loi_str)
                        self._status(loi_str)
                    self.last_processed_index = idx
                except Exception as e:
                    loi_str = f"Exception khi kiểm tra IP/HTTP module: {e}"
                    print("[ERROR]", loi_str)
                    in_ra_loi_khong_dau(loi_str)
                    self.file_processed.emit(idx, name, loi_str)
                    self._status(loi_str)
                    self.last_processed_index = idx
                    continue

                print(f"[INFO] Hoàn thành xử lý cho '{name_nodiac}' (index {idx}). Chuyển sang wifi tiếp theo nếu có.")
            print("[INFO] Hoàn thành chuỗi xử lý.")
            self.status_update.emit("Hoàn thành!.")
            self.finished.emit()
        except Exception as e:
            in_ra_loi_khong_dau(f"Lỗi ProcessWorker.run: {e}")
            print("[FATAL ERROR]", f"Lỗi ProcessWorker.run: {e}")
            try:
                self.toggle_polling.emit(False)
            except Exception:
                pass
            self.finished.emit()

class NetStatusWorker(QObject):
    status = Signal(str, bool, str)

    def __init__(self, interval_ms=3000):
        super().__init__()
        self._interval_ms = interval_ms
        self._timer = None
        self._paused = False

    @Slot()
    def start(self):
        if self._timer is None:
            self._timer = QTimer(self)
            self._timer.setInterval(self._interval_ms)
            self._timer.timeout.connect(self.poll)
        if not self._paused:
            self._timer.start()

    @Slot()
    def stop(self):
        if self._timer:
            QMetaObject.invokeMethod(self._timer, "stop", QtCoreQt.QueuedConnection)

    @Slot(bool)
    def set_paused(self, pause):
        self._paused = bool(pause)
        if self._timer:
            if self._paused:
                QMetaObject.invokeMethod(self._timer, "stop", QtCoreQt.QueuedConnection)
            else:
                QMetaObject.invokeMethod(self._timer, "start", QtCoreQt.QueuedConnection)

    @Slot()
    def poll(self):
        try:
            ssid = get_current_ssid()
            gateway = get_default_gateway()
            if gateway == MODULE_HOST:
                module_ok = True
                module_msg = "Đã kết nối với thiết bị, sẵn sàng làm việc!"
            elif gateway:
                module_ok = False
                module_msg = f"Sai mạng, vui lòng kết nối tới wifi được phát ra từ module! Mạng hiện tại: {gateway}."
            else:
                module_ok = False
                module_msg = "Không lấy được thông tin mạng."
            self.status.emit(ssid, module_ok, module_msg)
        except Exception as e:
            in_ra_loi_khong_dau(f"Lỗi NetStatusWorker.poll: {e}")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("MENJMOI")
        self.setWindowIcon(QIcon(get_app_logo_pixmap()))
        self.resize(1000, 700)
        self.checker = KeyChecker()
        self.login_page = LoginPage(self.checker)
        self.main_page = MainPage()
        self.stack = QStackedWidget()
        self.stack.addWidget(self.login_page)
        self.stack.addWidget(self.main_page)

        container = QWidget()
        v = QVBoxLayout(container)
        v.setContentsMargins(0, 0, 0, 0)
        v.addWidget(self.stack)
        self.setCentralWidget(container)

        self._setup_header_footer()
        self.apply_styles()

        self.net_thread = QThread(self)
        self.net_worker = NetStatusWorker(interval_ms=3000)
        self.net_worker.moveToThread(self.net_thread)
        self.net_thread.started.connect(self.net_worker.start)
        self.net_worker.status.connect(lambda ssid, ok, msg: (
            self.main_page.update_wifi_status(ssid, ok),
            self.main_page.update_process_status(msg)
        ))
        self.net_thread.start()

        QApplication.instance().aboutToQuit.connect(self._graceful_shutdown)
        self.net_thread.finished.connect(self.net_worker.deleteLater)

        self.login_page.key_validated.connect(self.on_key_validated)
        self.main_page.start_btn.clicked.connect(self.on_start)
        self.main_page.stop_btn.clicked.connect(self.on_stop)

        self.splash = None
        self.worker = None
        self.worker_stop_flag = threading.Event()
        self.try_auto_login()
        run_effect()

    def closeEvent(self, e):
        self._graceful_shutdown()
        super().closeEvent(e)

    def _graceful_shutdown(self):
        try:
            if getattr(self, "worker", None) and self.worker.isRunning():
                self.worker_stop_flag.set()
                self.worker.wait(5000)
        except Exception:
            pass

        for t in (getattr(self, "_ocr_thread", None), getattr(self, "auto_thread", None)):
            try:
                if t and t.isRunning():
                    if hasattr(t, "requestInterruption"):
                        t.requestInterruption()
                    t.wait(3000)
            except Exception:
                pass

        try:
            self.net_worker.set_paused(True)
            self.net_worker.stop()
        except Exception:
            pass
        try:
            if self.net_thread and self.net_thread.isRunning():
                self.net_thread.quit()
                self.net_thread.wait(3000)
        except Exception:
            pass

    def _setup_header_footer(self):
        header = QWidget()
        header.setFixedHeight(60)
        header.setStyleSheet("""
            background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #0a1830, stop:1 #223355);
        """)
        hbox = QHBoxLayout(header)
        title = QLabel("Scan & Clone Wifi")
        title.setStyleSheet("font-size:18px; font-weight:bold; color:#fff;")
        hbox.addWidget(title)
        hbox.addStretch()
        self.user_label = QLabel(f"MENJMOI V{app_version}")
        self.user_label.setStyleSheet("color:#1abc9c;")
        hbox.addWidget(self.user_label)

        footer = QWidget()
        footer.setFixedHeight(30)
        footer.setStyleSheet("background: #182a3a;")
        fbox = QHBoxLayout(footer)
        self.info_label = QLabel(self._get_footer_info_text())
        self.info_label.setStyleSheet("color:#aaa; font-size:11px;")
        fbox.addWidget(self.info_label)
        fbox.addStretch()
        contact = QLabel('<span style="color:#1abc9c;">Liên hệ admin: t.me/menjmoi</span>')
        contact.setStyleSheet("font-size:11px;")
        fbox.addWidget(contact)

        base = self.centralWidget()
        wrapper = QVBoxLayout()
        wrapper.setContentsMargins(0, 0, 0, 0)
        wrapper.addWidget(header)
        wrapper.addWidget(self.stack)
        wrapper.addWidget(footer)
        container = QWidget()
        container.setLayout(wrapper)
        self.setCentralWidget(container)

    def apply_styles(self):
        stylesheet = """
        QWidget { background-color: #101c2c; color: #f0f8ff; font-family: 'Segoe UI', Arial, sans-serif; }
        QPushButton { background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #1e2a3a, stop:1 #0a1830); border-radius:6px; padding:6px 14px; color:#fff; font-weight:bold; }
        QPushButton:hover { background: #1abc9c; color: #101c2c; }
        QLineEdit, QSpinBox { background: #182a3a; border:1px solid #223355; border-radius:4px; padding:4px; }
        QGroupBox { border: 1px solid #223355; border-radius:8px; margin-top:8px; }
        QGroupBox:title { subcontrol-origin: margin; left:10px; padding:0 5px; }
        QListWidget { background: #182a3a; border:1px solid #223355; }
        QTableWidget { background: #182a3a; gridline-color: #223355; }
        QHeaderView::section { background: #223355; padding:4px; }
        QLabel { font-size:13px; }
        """
        self.setStyleSheet(stylesheet)

    def _get_footer_info_text(self):
        user = USER_INFO.get("user_name")
        exp = USER_INFO.get("expiry_date")
        if user and exp:
            return f"User: {user} | Hạn sử dụng: {exp}"
        else:
            return "2025 MENJMOI"

    class AutoLoginThread(QThread):
        result = Signal(bool, str, str)
        def __init__(self, checker, key):
            super().__init__()
            self.checker = checker
            self.key = key
        def run(self):
            ok, msg = self.checker.check_key(self.key)
            self.result.emit(ok, msg, self.key)

    def show_splash(self, message="Đang kiểm tra key, vui lòng chờ..."):
        if self.splash is not None:
            return
        pixmap = QPixmap(500, 200)
        pixmap.fill(Qt.transparent)
        from PySide6.QtGui import QPainter, QColor
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.fillRect(pixmap.rect(), QColor("#101c2c"))
        painter.setPen(QColor("#1abc9c"))
        font = QFont("Segoe UI", 18, QFont.Bold)
        painter.setFont(font)
        painter.drawText(pixmap.rect(), Qt.AlignCenter, message)
        painter.end()
        self.splash = QSplashScreen(pixmap)
        self.splash.setWindowFlag(Qt.WindowStaysOnTopHint)
        self.splash.show()
        QApplication.processEvents()

    def hide_splash(self):
        if self.splash is not None:
            self.splash.close()
            self.splash = None

    def update_footer_info(self):
        if hasattr(self, "info_label"):
            self.info_label.setText(self._get_footer_info_text())

    def try_auto_login(self):
        def do_check():
            if os.path.isfile("key.txt"):
                try:
                    with open("key.txt", "r", encoding="utf-8") as f:
                        key = f.read().strip()
                    if not key:
                        self.stack.setCurrentWidget(self.login_page)
                        return
                    self.show_splash("Đang kiểm tra key, vui lòng chờ...")
                    self.auto_thread = self.AutoLoginThread(self.checker, key)
                    self.auto_thread.result.connect(self.after_auto_check)
                    self.auto_thread.finished.connect(lambda: setattr(self, 'auto_thread', None))
                    self.auto_thread.start()
                except Exception:
                    self.stack.setCurrentWidget(self.login_page)
            else:
                self.stack.setCurrentWidget(self.login_page)
        QTimer.singleShot(0, do_check)

    def after_auto_check(self, ok, msg, key):
        self.hide_splash()
        if ok:
            self.update_footer_info()
            self.show_splash("Key hợp lệ! Đang vào chương trình...")
            QTimer.singleShot(500, self._finish_auto_login)
        else:
            self.stack.setCurrentWidget(self.login_page)
            if hasattr(self.login_page, "status_label"):
                self.login_page.status_label.setText(f"{msg}")

    def _finish_auto_login(self):
        self.hide_splash()
        self.stack.setCurrentWidget(self.main_page)

    def on_key_validated(self, key):
        try:
            with open("key.txt", "w", encoding="utf-8") as f:
                f.write(key)
        except Exception:
            pass
        self.stack.setCurrentWidget(self.main_page)
        self.update_footer_info()

    def refresh_network_status(self):
        try:
            ssid = get_current_ssid()
            gateway = get_default_gateway()
            if gateway == MODULE_HOST:
                module_ok = True
                module_msg = "Đã kết nối với thiết bị, sẵn sàng làm việc!"
            elif gateway:
                module_ok = False
                module_msg = f"Sai mạng, vui lòng kết nối tới wifi được phát ra từ module! Mạng hiện tại: {gateway}."
            else:
                module_ok = False
                module_msg = "Không lấy được thông tin mạng."
            self.main_page.update_wifi_status(ssid, module_ok)
            self.main_page.update_process_status(module_msg)
        except Exception as e:
            in_ra_loi_khong_dau(f"Lỗi refresh_network_status: {e}")

    def on_start(self):
        try:
            files = self.main_page.selected_files
            ocr_results = getattr(self.main_page, "ocr_results", None)
            if not ocr_results:
                QMessageBox.warning(self, "Chưa có dữ liệu", "Chưa có dữ liệu hợp lệ để xử lý.")
                return
            if not any(e.get("ok") for e in ocr_results):
                QMessageBox.warning(self, "Chưa sẵn sàng", "Vui lòng xử lý ảnh hoặc nhập Name/Mac hợp lệ trước.")
                return
            lifetime = self.main_page.lifetime_spin.value()
            password = self.main_page.password_edit.text()
            self.main_page.update_process_status(f"Bắt đầu clone wifi từ {len([e for e in ocr_results if e.get('ok')])} mục hợp lệ...")
            start_index = self.main_page.last_processed_index + 1 if self.main_page.last_processed_index >= 0 else 0
            self.worker_stop_flag.clear()
            self.worker = ProcessWorker(
                ocr_results=ocr_results,
                files=files,
                lifetime=lifetime,
                password=password,
                start_index=start_index,
                stop_flag=self.worker_stop_flag
            )
            self.worker.file_processed.connect(self.handle_file_processed)
            self.worker.status_update.connect(self.main_page.update_process_status)
            self.worker.finished.connect(self.on_worker_finished)
            self.worker.toggle_polling.connect(self.net_worker.set_paused)

            self.main_page.start_btn.setVisible(False)
            self.main_page.stop_btn.setVisible(True)
            self.main_page.stop_btn.setEnabled(True)
            self.worker.start()
        except Exception as e:
            in_ra_loi_khong_dau(f"Lỗi on_start: {e}")

    def on_stop(self):
        try:
            if self.worker is not None and self.worker.isRunning():
                self.worker_stop_flag.set()
                self.main_page.update_process_status("Đang dừng, vui lòng đợi...")
                self.worker.wait(5000)
            try:
                self.net_worker.set_paused(False)
            except Exception:
                pass
            self.main_page.start_btn.setVisible(True)
            self.main_page.stop_btn.setVisible(False)
        except Exception as e:
            in_ra_loi_khong_dau(f"Lỗi on_stop: {e}")

    def on_worker_finished(self):
        if self.worker is not None and hasattr(self.worker, "last_processed_index"):
            self.main_page.last_processed_index = self.worker.last_processed_index
        else:
            self.main_page.last_processed_index = -1
        self.main_page.start_btn.setVisible(True)
        self.main_page.stop_btn.setVisible(False)
        self.main_page.update_process_status("Hoàn thành chuỗi xử lý.")
        try:
            self.net_worker.set_paused(False)
        except Exception:
            pass

    def handle_file_processed(self, idx, name, status):
        try:
            if 0 <= idx < len(self.main_page.ocr_results):
                mac = self.main_page.ocr_results[idx].get("mac", "")
                self.main_page.set_processing_result(idx, name, mac, status)
        except Exception as e:
            in_ra_loi_khong_dau(f"Lỗi handle_file_processed: {e}")

def main():
    try:
        app = QApplication(sys.argv)
        stylesheet = """
        QWidget { background-color: #101c2c; color: #f0f8ff; font-family: 'Segoe UI', Arial, sans-serif; }
        QPushButton { background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #1e2a3a, stop:1 #0a1830); border-radius:6px; padding:6px 14px; color:#fff; font-weight:bold; }
        QPushButton:hover { background: #1abc9c; color: #101c2c; }
        QLineEdit, QSpinBox { background: #182a3a; border:1px solid #223355; border-radius:4px; padding:4px; }
        QGroupBox { border: 1px solid #223355; border-radius:8px; margin-top:8px; }
        QGroupBox:title { subcontrol-origin: margin; left:10px; padding:0 5px; }
        QListWidget { background: #182a3a; border:1px solid #223355; }
        QTableWidget { background: #182a3a; gridline-color: #223355; }
        QHeaderView::section { background: #223355; padding:4px; }
        QLabel { font-size:13px; }
        """
        app.setStyleSheet(stylesheet)
        window = MainWindow()
        window.show()
        sys.exit(app.exec())
    except Exception as e:
        in_ra_loi_khong_dau(f"Loi main: {e}", e)

if __name__ == "__main__":
    main()
