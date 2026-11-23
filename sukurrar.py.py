# -*- coding: utf-8 -*-
"""
SukurRAR Service — фоновый архиватор-сторож.

Команды:
  python sukur_service.py install              — автозапуск (текущий пользователь)
  python sukur_service.py run                  — фоновый цикл
  python sukur_service.py pack   <путь>        — зашифрованный бэкап прямо сейчас
  python sukur_service.py unpack <архив> <куда> — распаковка по паролю
"""
import sys
import time
import secrets
import hashlib
import json
import winreg
from pathlib import Path
from datetime import datetime

import pyzipper
import requests
import win32crypt

# ------------------------------ настройки ----------------------------------

VT_API_KEY = "ВСТАВЬ_КЛЮЧ_VIRUSTOTAL"

WATCH_DIR  = Path.home() / "Downloads"
BASE_DIR   = Path(r"D:\SukurRAR")
QUARANTINE = BASE_DIR / "quarantine"
BACKUP_DIR = BASE_DIR / "backups"
STATE_FILE = BASE_DIR / "state.json"
KEY_FILE   = BASE_DIR / "key.bin"
LOG_FILE   = BASE_DIR / "service.log"

BACKUP_SOURCES = [r"C:\Users\Ты\Documents"]  # впиши свои папки
BACKUP_INTERVAL_HOURS = 24
CHECK_INTERVAL_SEC = 20

PROTECTED = [r"C:\Windows", r"C:\Program Files",
             r"C:\Program Files (x86)", r"C:\ProgramData"]


# ------------------------------- утилиты ------------------------------------

def log(msg):
    line = "[%s] %s" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg)
    print(line, flush=True)
    try:
        BASE_DIR.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def is_protected(path: Path) -> bool:
    try:
        real = str(path.resolve()).lower()
        for zone in PROTECTED:
            if real == zone.lower() or real.startswith(zone.lower() + "\\"):
                return True
    except OSError:
        pass
    return False


def sha256_file(p: Path):
    h = hashlib.sha256()
    try:
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


# ------------------------- пароль: DPAPI-хранилище --------------------------

def load_password() -> bytes:
    """Пароль бэкапов. Хранится зашифрованным для текущего пользователя,
    расшифровать может только он, на этом же компьютере."""
    if KEY_FILE.exists():
        _desc, pw = win32crypt.CryptUnprotectData(
            KEY_FILE.read_bytes(), None, None, None, 0)
        return pw
    KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    pw = secrets.token_urlsafe(18).encode()
    blob = win32crypt.CryptProtectData(pw, "SukurRAR", None, None, None, 0)
    KEY_FILE.write_bytes(blob)
    log("Создан новый ключ шифрования бэкапов (DPAPI).")
    return pw


# ----------------------------- VirusTotal -----------------------------------

def vt_check(p: Path) -> int:
    """-1 — не удалось проверить, иначе число антивирусов с вердиктом зловред."""
    h = sha256_file(p)
    if h is None:
        return -1
    try:
        r = requests.get("https://www.virustotal.com/api/v3/files/%s" % h,
                         headers={"x-apikey": VT_API_KEY}, timeout=30)
        if r.status_code == 404:
            return 0
        if r.status_code == 429:
            return -1
        r.raise_for_status()
        st = r.json()["data"]["attributes"]["last_analysis_stats"]
        return st["malicious"]
    except requests.RequestException:
        return -1


def watch_downloads(seen: set):
    QUARANTINE.mkdir(parents=True, exist_ok=True)
    try:
        entries = list(WATCH_DIR.iterdir())
    except OSError:
        return
    for p in entries:
        if not p.is_file() or p.name in seen:
            continue
        seen.add(p.name)
        verdict = vt_check(p)
        if verdict > 0:
            dest = QUARANTINE / datetime.now().strftime("%Y%m%d_%H%M%S")
            dest.mkdir(parents=True, exist_ok=True)
            try:
                p.rename(dest / p.name)
                log("ЗЛОВРЕД (%d антивирусов), перемещён в карантин: %s"
                    % (verdict, p.name))
            except OSError as e:
                log("Не удалось переместить %s: %s" % (p.name, e))
        elif verdict == -1:
            log("Не удалось проверить (сеть или лимит): %s" % p.name)
        else:
            log("Чисто: %s" % p.name)


# ------------------------------- бэкапы --------------------------------------

def do_pack(src: Path, dst: Path) -> bool:
    if is_protected(src):
        log("ОТКАЗ: %s — системная зона, защита файловой системы." % src)
        return False
    password = load_password()
    try:
        files = ([src] if src.is_file()
                 else [p for p in src.rglob("*") if p.is_file()])
        with pyzipper.AESZipFile(dst, "w", compression=pyzipper.ZIP_DEFLATED,
                                 encryption=pyzipper.WZ_AES) as zf:
            zf.setpassword(password)
            for f in files:
                zf.write(f, f.relative_to(src.parent))
        log("Бэкап создан: %s (%d файлов)" % (dst, len(files)))
        return True
    except (OSError, Exception) as e:
        log("Ошибка бэкапа %s: %s" % (src, e))
        return False


def backup_tick(state: dict):
    now = time.time()
    last = state.get("last_backup", 0)
    if now - last < BACKUP_INTERVAL_HOURS * 3600:
        return
    stamp = datetime.now().strftime("%Y-%m-%d_%H%M")
    ok = 0
    for s in BACKUP_SOURCES:
        src = Path(s)
        if not src.exists():
            log("Папка бэкапа не найдена: %s" % s)
            continue
        dst = BACKUP_DIR / ("%s_%s.zip" % (src.name.replace(" ", "_"), stamp))
        if do_pack(src, dst):
            ok += 1
    if ok:
        state["last_backup"] = now
        save_state(state)


# ------------------------------- состояние -----------------------------------

def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_state(state: dict):
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(state), encoding="utf-8")
    except OSError:
        pass


# ------------------------------ автозапуск -----------------------------------

def cmd_install():
    here = Path(__file__).resolve()
    run_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    cmd = 'pythonw.exe "%s" run' % here
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, run_key, 0,
                            winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "SukurRAR", 0, winreg.REG_SZ, cmd)
        log("Автозапуск установлен: HKCU\\...\\Run\\SukurRAR -> %s" % cmd)
        print("[+] Готово. Служба стартует при входе в систему "
              "и запускается прямо сейчас.")
    except OSError as e:
        print("[!] Не удалось прописать автозапуск: %s" % e)


# --------------------------------- цикл ---------------------------------------

def cmd_run():
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    state = load_state()
    seen = set(p.name for p in WATCH_DIR.iterdir() if p.is_file()) \
        if WATCH_DIR.exists() else set()
    log("Служба запущена. Наблюдаю: %s" % WATCH_DIR)
    while True:
        try:
            watch_downloads(seen)
            backup_tick(state)
        except Exception as e:
            log("Ошибка цикла: %s" % e)
        time.sleep(CHECK_INTERVAL_SEC)


# ------------------------------ распаковка ------------------------------------

def cmd_unpack(archive: str, dest: str):
    arch, dst = Path(archive), Path(dest)
    if is_protected(dst):
        print("[!] Ошибка безопасности: нельзя распаковывать "
              "в системные папки.")
        return
    try:
        password = load_password()
    except OSError:
        print("[!] Ключ бэкапов недоступен. Архивы, сделанные вручную "
              "с другим паролем, распаковывай по этому паролю.")
        return
    try:
        with pyzipper.AESZipFile(arch) as zf:
            names = zf.namelist()
            if names:
                zf.read(names[0], pwd=password)  # проверка пароля заранее
            for name in names:
                zf.extract(name, dst, pwd=password)
        print("[+] Распаковано %d файлов в %s" % (len(names), dst))
    except RuntimeError:
        print("[!] Не подошёл пароль.")
    except Exception:
        print("[!] Архив повреждён или это не ZIP.")


# -------------------------------- main ----------------------------------------

def main():
    cmds = {
        "install": (cmd_install, 0),
        "run":     (cmd_run, 0),
        "unpack":  (cmd_unpack, 2),
    }
    if len(sys.argv) >= 2 and sys.argv[1] == "pack" and len(sys.argv) >= 3:
        src = Path(sys.argv[2])
        stamp = datetime.now().strftime("%Y-%m-%d_%H%M")
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        do_pack(src, BACKUP_DIR / ("%s_%s.zip" % (src.name, stamp)))
        return
    if len(sys.argv) < 2 or sys.argv[1] not in cmds:
        print(__doc__)
        return
    fn, nargs = cmds[sys.argv[1]]
    args = sys.argv[2:]
    if len(args) < nargs:
        print(__doc__)
        return
    fn(*args)


if __name__ == "__main__":
    main()

