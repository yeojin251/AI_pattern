# app.py — Capstone Secure Keyboard (GUI + 대시보드 + 패턴학습 + 실시간 검증)
# 요구 패키지: requests, pynput, cryptography, fastapi, uvicorn, psutil

import threading, asyncio, time, secrets, hmac, hashlib, requests, webbrowser, json, psutil
from tkinter import Tk, Label, Entry, Button, StringVar, DISABLED, NORMAL, Frame
from typing import Set
from pynput import keyboard
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn

# 11/11
import tkinter.font as font
from tkinter import Tk, StringVar, DISABLED, NORMAL
from tkinter import font as tkfont
from tkinter import ttk

# ========= 설정 =========
API_BASE = "http://127.0.0.1:5000"  # Flask 서버 주소 (server.py)
SIGNUP_URL = (
    "http://127.0.0.1:5500/index.html"  # 회원가입 페이지 (없으면 빈 문자열로 두세요)
)

DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 8765


# ========= 서버 API =========
def api_login(username: str, password: str) -> str:
    r = requests.post(
        f"{API_BASE}/api/login",
        json={"username": username, "password": password},
        timeout=10,
    )
    if r.status_code != 200:
        try:
            msg = r.json().get("error")
        except Exception:
            msg = None
        raise RuntimeError(msg or f"로그인 실패 (HTTP {r.status_code})")
    return r.json()["token"]


def api_get_ascii_map(token: str):
    r = requests.get(
        f"{API_BASE}/api/me/ascii-map",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    if r.status_code != 200:
        try:
            msg = r.json().get("error")
        except Exception:
            msg = None
        raise RuntimeError(msg or f"매핑 조회 실패 (HTTP {r.status_code})")
    data = r.json()
    mapping = {chr(int(k)): chr(v) for k, v in data["asciiMap"].items()}
    return mapping, data["version"]


# ========= 세션키 파생 =========
def derive_session_key(user_secret: bytes, salt: bytes) -> bytes:
    return hmac.new(user_secret, salt, hashlib.sha256).digest()  # 32B AES-256


# ========= 암호화기 =========
class AESEncryptor:
    def __init__(self, key: bytes):
        assert len(key) == 32
        self.key = key
        self.aesgcm = AESGCM(self.key)
        self.nonce = secrets.token_bytes(12)  # 데모용 (서비스는 per-message 권장)

    def encrypt_byte(self, b: bytes) -> bytes:
        return self.aesgcm.encrypt(self.nonce, b, None)


# ========= 내장 대시보드 서버 =========
DASHBOARD_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>Keyboard Security Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body{font-family:system-ui;margin:16px}
.grid{display:grid;grid-template-columns:repeat(19,1fr);gap:6px}
.cell{border:1px solid #ddd;padding:6px;text-align:center;border-radius:8px}
.row{display:flex;gap:16px;margin-bottom:16px}
table{border-collapse:collapse;width:100%}
th,td{border-bottom:1px solid #eee;padding:6px 8px}
small{color:#777}
</style></head><body>
<h2>Real-Time Keyboard Security Dashboard</h2>
<div class="row">
  <div style="flex:2">
    <h3>입력 → 매핑 → 암호문</h3>
    <table id="log"><thead>
      <tr><th>시간</th><th>입력</th><th>매핑</th><th>암호문(hex, 앞부분)</th></tr>
    </thead><tbody></tbody></table>
  </div>
  <div style="flex:1">
    <h3>CPU 사용률(%)</h3>
    <canvas id="cpuChart"></canvas>
    <div id="cryptoMs" style="margin-top:8px;color:#555"></div>
    <small>프로세스 전체 CPU 사용률. 입력 시 암호화 구간(ms)이 갱신됩니다.</small>
  </div>
</div>
<h3>나의 ASCII 재정의 표</h3>
<div id="mapGrid" class="grid"></div>

<script>
const tbody = document.querySelector("#log tbody");
const cpuCtx = document.getElementById('cpuChart').getContext('2d');
const cpuData = {labels:[], datasets:[{label:'Process CPU %', data:[]}]};
const cpuChart = new Chart(cpuCtx, {type:'line', data:cpuData, options:{
  animation:false, responsive:true, scales:{y:{min:0,max:30}} }});
const ws = new WebSocket(`ws://${location.host}/ws`);

function addRow(ev){
  const tr = document.createElement("tr");
  const t = new Date(ev.ts*1000).toLocaleTimeString();
  tr.innerHTML = `<td>${t}</td><td>${ev.input}</td><td>${ev.mapped}</td><td>${ev.cipher_hex}</td>`;
  tbody.prepend(tr);
  while(tbody.rows.length>20) tbody.deleteRow(20);
}
ws.onmessage = (msg)=>{
  const data = JSON.parse(msg.data);
  if(data.type === "event"){ addRow(data); }
  else if(data.type === "cpu"){
    const ts = new Date().toLocaleTimeString();
    cpuData.labels.push(ts);
    cpuData.datasets[0].data.push(data.proc_cpu);
    if(cpuData.labels.length>60){ cpuData.labels.shift(); cpuData.datasets[0].data.shift(); }
    cpuChart.update();
    document.getElementById("cryptoMs").textContent =
      `최근 암호화 구간: ${data.crypto_ms.toFixed(3)} ms`;
  } else if (data.type === "close") { window.close(); }
};
fetch("/mapping").then(r=>r.json()).then(MAP=>{
  const grid = document.getElementById("mapGrid");
  const ascii = Array.from({length:95},(_,i)=>String.fromCharCode(i+32));
  ascii.forEach(ch=>{
    const div = document.createElement("div");
    div.className="cell";
    div.textContent = `${ch} → ${MAP[ch]||'?'}`;
    grid.appendChild(div);
  });
});
</script>
</body></html>"""


class DashboardServer:
    def __init__(self, mapping_getter, crypto_ms_getter):
        self.mapping_getter = mapping_getter
        self.crypto_ms_getter = crypto_ms_getter
        self.loop = None
        self.thread = None
        self.app = None
        self.server = None
        self.event_q = None
        self.clients: Set[WebSocket] = set()
        self.proc = psutil.Process()
        self.proc.cpu_percent(interval=None)

        self.host = DASHBOARD_HOST  # 호스트/포트 저장
        self.port = DASHBOARD_PORT

    def push_event(self, ch: str, remapped: str, cipher_hex: str):
        if not (self.loop and self.event_q):
            return
        ev = {
            "type": "event",
            "ts": time.time(),
            "input": ch,
            "mapped": remapped,
            "cipher_hex": cipher_hex[:40],
        }
        self.loop.call_soon_threadsafe(self.event_q.put_nowait, ev)

    def start(self, host=DASHBOARD_HOST, port=DASHBOARD_PORT):
        if self.thread:
            return
        self.host = host
        self.port = port
        self.thread = threading.Thread(target=self._run, args=(host, port), daemon=True)
        self.thread.start()
        webbrowser.open(f"http://{host}:{port}/")

    def _run(self, host, port):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.event_q = asyncio.Queue()
        self.app = FastAPI()
        app = self.app

        @app.get("/")
        def index():
            return HTMLResponse(DASHBOARD_HTML)

        @app.get("/mapping")
        def mapping():
            try:
                return JSONResponse(self.mapping_getter() or {})
            except Exception:
                return JSONResponse({})

        @app.websocket("/ws")
        async def ws_endpoint(ws: WebSocket):
            await ws.accept()
            self.clients.add(ws)
            try:
                while True:
                    await asyncio.sleep(1.0)
            finally:
                self.clients.discard(ws)

        async def broadcaster_task():
            last_cpu_push = 0.0
            while True:
                try:
                    ev = await asyncio.wait_for(self.event_q.get(), timeout=0.2)
                    dead = []
                    for ws in list(self.clients):
                        try:
                            await ws.send_text(json.dumps(ev))
                        except Exception:
                            dead.append(ws)
                    for d in dead:
                        self.clients.discard(d)
                except asyncio.TimeoutError:
                    pass

                now = time.time()
                if now - last_cpu_push >= 0.5:
                    payload = {
                        "type": "cpu",
                        "proc_cpu": self.proc.cpu_percent(interval=None),
                        "crypto_ms": float(self.crypto_ms_getter() or 0.0),
                    }
                    dead = []
                    for ws in list(self.clients):
                        try:
                            await ws.send_text(json.dumps(payload))
                        except Exception:
                            dead.append(ws)
                    for d in dead:
                        self.clients.discard(d)
                    last_cpu_push = now

        config = uvicorn.Config(
            app, host=host, port=port, log_level="warning", loop="asyncio"
        )
        self.server = uvicorn.Server(config)
        task = self.loop.create_task(broadcaster_task())
        try:
            self.loop.run_until_complete(self.server.serve())
        finally:
            task.cancel()
            try:
                self.loop.run_until_complete(task)
            except Exception:
                pass

    def push_close_signal(self):
        if self.loop and self.loop.is_running():

            async def _broadcast_close():
                msg = json.dumps({"type": "close"})
                await asyncio.gather(
                    *[ws.send_text(msg) for ws in list(self.clients)],
                    return_exceptions=True,
                )

            fut = asyncio.run_coroutine_threadsafe(_broadcast_close(), self.loop)
            try:
                fut.result(timeout=1.0)
            except Exception:
                pass

    def stop(self):
        if self.loop and self.server:
            self.loop.call_soon_threadsafe(setattr, self.server, "should_exit", True)
        if self.thread:
            self.thread.join(timeout=2.0)
        self.thread = None
        self.loop = None
        self.app = None
        self.server = None
        self.clients.clear()


# ========= 후킹 + 수집 + 실시간 검증 =========
class HookEngine:
    def __init__(
        self,
        mapping,
        encryptor,
        ui_status_cb,
        dashboard=None,
        api_base=API_BASE,
        api_token=None,
    ):
        self.mapping = mapping
        self.encryptor = encryptor
        self.ui_status_cb = ui_status_cb
        self.dashboard = dashboard
        self.api_base = api_base
        self.api_token = api_token

        self._listener = None
        self._running = False
        self.total_time = 0.0
        self.last_crypto_ms = 0.0

        # 수집 상태
        self.learn_active = False
        self.learn_session_id = None
        self.learn_buf = []
        self.learn_lock = threading.Lock()
        self.down_map = {}  # code -> (t_down_mono, ts_down_epoch_ms)
        self.last_up_mono = None
        self.last_up_code = None

        self._flush_thread = None
        self._flush_stop = threading.Event()

        # 실시간 인증 버퍼 및 주기 플러시
        self.verify_buf = []
        self.verify_lock = threading.Lock()
        self.VERIFY_BATCH_SIZE = 8  # 빠른 피드백
        self.VERIFY_FLUSH_SEC = 2.0  # 2초 이상 대기하면 강제 전송
        self._verify_timer = None
        self._last_verify_send = 0.0

    def _code_of(self, key):
        try:
            return f"Char.{key.char}"
        except AttributeError:
            try:
                return f"Key.{key.name}"
            except Exception:
                return str(key)

    def _headers(self):
        return (
            {
                "Authorization": f"Bearer {self.api_token}",
                "Content-Type": "application/json",
            }
            if self.api_token
            else {"Content-Type": "application/json"}
        )

    # ====== 서버 통신(학습) ======
    def start_learning(self, min_events=600, policy="threshold"):
        if self.learn_active:
            return
        if not self.api_token:
            raise RuntimeError("토큰 없음: 로그인 후 사용하세요.")
        r = requests.post(
            f"{self.api_base}/api/pattern/start",
            headers=self._headers(),
            json={"min_events": int(min_events), "policy": policy},
            timeout=10,
        )
        j = r.json()
        if not r.ok or not j.get("ok"):
            raise RuntimeError(f"start 실패: {j}")
        self.learn_session_id = j["session_id"]
        self.learn_active = True
        self._flush_stop.clear()
        self._flush_thread = threading.Thread(target=self._flush_daemon, daemon=True)
        self._flush_thread.start()

    def stop_learning(self):
        if not self.learn_active:
            return
        try:
            self._flush_once(force=True)
            requests.post(
                f"{self.api_base}/api/pattern/stop",
                headers=self._headers(),
                json={"session_id": self.learn_session_id},
                timeout=5,
            )
        finally:
            self.learn_active = False
            self.learn_session_id = None
            self._flush_stop.set()
            if self._flush_thread:
                self._flush_thread.join(timeout=2.0)
                self._flush_thread = None

    def _flush_daemon(self):
        while not self._flush_stop.is_set():
            self._flush_once()
            self._flush_stop.wait(1.5)

    def _flush_once(self, force=False):
        if not self.learn_active or not self.learn_session_id:
            return
        with self.learn_lock:
            if not self.learn_buf:
                return
            if not force and len(self.learn_buf) < 120:
                return
            batch = self.learn_buf[:]
            self.learn_buf.clear()
        try:
            r = requests.post(
                f"{self.api_base}/api/pattern/collect",
                headers=self._headers(),
                json={"session_id": self.learn_session_id, "samples": batch},
                timeout=10,
            )
            j = r.json()
            if j.get("stop"):
                self.learn_active = False
                self.learn_session_id = None
                self.ui_status_cb(f"패턴 학습 자동 종료(총 {j.get('total',0)} 이벤트).")
        except Exception as e:
            # 수집 에러는 조용히 무시(원한다면 print로만 로깅)
            # print(f"[collect] error: {e}")
            pass

    # ====== 실시간 인증 ======
    def _verify_typing_pattern(self, forced=False):
        with self.verify_lock:
            if not self.verify_buf:
                return
            batch = self.verify_buf[:]
            self.verify_buf.clear()

        try:
            r = requests.post(
                f"{self.api_base}/api/pattern/verify",
                headers=self._headers(),
                json={"samples": batch},
                timeout=6,
            )
            self._last_verify_send = time.time()
            if r.status_code == 200:
                result = r.json()
                auth_msg = "인증 성공" if result.get("is_user") else "인증 실패"
                # ✅ 정확도만 표시 (에러 메시지 UI 출력 없음)
                self.ui_status_cb(f"{auth_msg} · 정확도 {result.get('score')}")
            else:
                # ❌ 서버 오류 발생 시 UI에 표시하지 않음 (조용히 패스)
                # print(f"[verify] HTTP {r.status_code}: {r.text}")
                pass
        except Exception:
            # ❌ 네트워크 예외 등도 UI에 표시하지 않음 (조용히 패스)
            # print(f"[verify] exception: {e}")
            pass

    def _verify_timer_loop(self):
        # 일정 주기마다 버퍼가 조금이라도 있으면 강제 전송(사용자 피드백 지연 방지)
        while self._running:
            time.sleep(1.0)
            with self.verify_lock:
                has_buf = len(self.verify_buf) > 0
            if (
                has_buf
                and (time.time() - self._last_verify_send) >= self.VERIFY_FLUSH_SEC
            ):
                self._verify_typing_pattern(forced=True)

    # ====== 키 이벤트 ======
    def _on_press(self, key):
        # 암호화 & 대시보드
        try:
            ch = key.char
            if ch in self.mapping:
                remapped = self.mapping[ch]
                t0 = time.perf_counter()
                ct = self.encryptor.encrypt_byte(remapped.encode("utf-8"))
                self.last_crypto_ms = (time.perf_counter() - t0) * 1000.0
                self.total_time += self.last_crypto_ms
                if self.dashboard:
                    self.dashboard.push_event(ch, remapped, ct.hex())
        except AttributeError:
            pass

        # 학습: keydown 기록
        code = self._code_of(key)
        if code not in self.down_map:
            self.down_map[code] = (
                time.perf_counter(),
                round(time.time() * 1000, 3),
            )  # mono, epoch_ms

    def _on_release(self, key):
        code = self._code_of(key)
        t_up_mono = time.perf_counter()
        if code in self.down_map:
            t_down_mono, ts_down_epoch_ms = self.down_map.pop(code)
            dwell = (t_up_mono - t_down_mono) * 1000.0  # ms
            flight = (
                None
                if self.last_up_mono is None
                else (t_down_mono - self.last_up_mono) * 1000.0
            )
            ts_up_epoch_ms = round(time.time() * 1000, 3)
            try:
                kchar = key.char
            except AttributeError:
                kchar = ""

            # 학습 버퍼
            if self.learn_active:
                sample = {
                    "ts_down": ts_down_epoch_ms,
                    "ts_up": ts_up_epoch_ms,
                    "dwell": round(dwell, 3),
                    "flight": (None if flight is None else round(flight, 3)),
                    "code": code,
                    "prev_code": (self.last_up_code or ""),
                    "key": kchar or "",
                }
                with self.learn_lock:
                    self.learn_buf.append(sample)
                if len(self.learn_buf) >= 120:
                    self._flush_once(False)

            # 실시간 인증 버퍼(수집 여부와 무관)
            if flight is not None and dwell > 0:
                live = {
                    "ts_down": ts_down_epoch_ms,
                    "ts_up": ts_up_epoch_ms,
                    "dwell_ms": round(dwell, 3),
                    "flight_ms": round(flight, 3),
                    "code": code,
                    "prev_code": (self.last_up_code or ""),
                }
                with self.verify_lock:
                    self.verify_buf.append(live)
                    nbuf = len(self.verify_buf)
                # 배치 도달 시 즉시 검증
                if nbuf >= self.VERIFY_BATCH_SIZE:
                    threading.Thread(
                        target=self._verify_typing_pattern, daemon=True
                    ).start()

            self.last_up_mono = t_up_mono
            self.last_up_code = code

    def start(self):
        if self._running:
            return
        self._running = True
        self._listener = keyboard.Listener(
            on_press=self._on_press, on_release=self._on_release
        )
        self._listener.start()
        # 주기 플러시 타이머 시작
        self._verify_timer = threading.Thread(
            target=self._verify_timer_loop, daemon=True
        )
        self._verify_timer.start()
        self.ui_status_cb("암호화 ON (ESC로 종료 가능)")

    def stop(self):
        if self.learn_active:
            try:
                self.stop_learning()
            except:
                pass
        if self._listener:
            self._listener.stop()
        self._running = False
        self.ui_status_cb("암호화 OFF")


# 11/11
# (선택) ttkbootstrap 있으면 자동 사용
def _maybe_use_ttkbootstrap(root):
    try:
        import ttkbootstrap as tb

        style = tb.Style("darkly")  # darkly / flatly / minty 등
        return True
    except Exception:
        # 순정 ttk 사용
        style = ttk.Style()
        # 최신 느낌 나는 테마 & 컬러 세팅
        for th in ("clam", "vista", "alt"):
            if th in style.theme_names():
                style.theme_use(th)
                break
        # 공통 폰트
        default_font = tkfont.nametofont("TkDefaultFont")
        default_font.configure(size=11)
        tkfont.nametofont("TkTextFont").configure(size=11)
        tkfont.nametofont("TkHeadingFont").configure(size=13, weight="bold")

        # 색 구성 (라이트 기준)
        bg = "#F5F6F7"
        card = "#FFFFFF"
        fg = "#1F2937"
        sub = "#6B7280"
        prim = "#2563EB"  # 버튼 포커스/강조
        style.configure(".", background=bg, foreground=fg)
        style.configure("Card.TFrame", background=card, relief="flat")
        style.configure("Muted.TLabel", foreground=sub, background=card)
        style.configure("Muted1.TLabel", background=card)
        style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"), background=bg)
        style.configure("Title1.TLabel", font=("Segoe UI", 16, "bold"), background=card)
        style.configure(
            "Caption.TLabel", font=("Segoe UI", 10), foreground=sub, background=bg
        )
        style.configure(
            "Accent.TButton", padding=(12, 8), font=("Segoe UI", 11, "semibold")
        )
        style.map(
            "Accent.TButton",
            foreground=[("disabled", "#9CA3AF"), ("!disabled", "#ffffff")],
            background=[
                ("disabled", "#D1D5DB"),
                ("pressed", "#1D4ED8"),
                ("active", "#1E40AF"),
                ("!disabled", prim),
            ],
        )
        style.configure(
            "Link.TButton", relief="flat", padding=0, background=card, foreground=prim
        )
        style.map("Link.TButton", foreground=[("active", "#1D4ED8")])

        # Entry
        style.configure("TEntry", padding=8, relief="flat")
        style.map("TEntry", fieldbackground=[("!disabled", "#FFFFFF")])

        # 라벨프레임/구분선
        style.configure("Section.TLabelframe", background=card)
        style.configure(
            "TLabelframe.Label", background=card, font=("Segoe UI", 11, "bold")
        )
        style.configure("TSeparator", background="#E5E7EB")

        # Statusbar
        style.configure("Status.TFrame", background=card)
        style.configure("Status.TLabel", background=card, foreground=sub)

        return False


# ========= GUI (리팩토링된 버전) =========
class App:
    def __init__(self):
        self.root = Tk()
        self.root.title("CapSecure — 실시간 키보드 암호화")
        self.root.geometry("880x600")
        self.root.minsize(720, 520)
        self.is_bootstrap = _maybe_use_ttkbootstrap(self.root)

        # 상태 값
        self.id_var = StringVar()
        self.pw_var = StringVar()
        self.msg_var = StringVar(
            value="로그인 후 매핑을 가져오고 대시보드를 열 수 있어요."
        )
        self._token = None
        self.hook = None
        self.dashboard = None
        self._toggle_busy = False
        self._learning = False
        self.mapping = {}  # 매핑 저장용

        # ===== 레이아웃 =====
        self._build_layout()

        # 종료 이벤트
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # -------- UI 빌드 --------
    def _build_layout(self):
        root = self.root
        root.grid_columnconfigure(0, weight=1)
        root.grid_rowconfigure(0, weight=1)

        shell = ttk.Frame(root, padding=16)
        shell.grid(row=0, column=0, sticky="nsew")
        shell.grid_columnconfigure(0, weight=1)
        shell.grid_rowconfigure(1, weight=1)

        # 헤더
        header = ttk.Frame(shell)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        header.grid_columnconfigure(0, weight=1)
        ttk.Label(header, text="CapSecure", style="Title.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        ttk.Label(
            header,
            text="BlockChain + Real-Time Keyboard Encryption",
            style="Caption.TLabel",
        ).grid(row=1, column=0, sticky="w")

        # 메인 2-컬럼
        main = ttk.Frame(shell)
        main.grid(row=1, column=0, sticky="nsew")
        main.grid_columnconfigure(0, weight=1, uniform="col")
        main.grid_columnconfigure(1, weight=2, uniform="col")
        main.grid_rowconfigure(0, weight=1)

        # (좌) 로그인 카드
        left_card = ttk.Frame(main, style="Card.TFrame", padding=20)
        left_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left_card.grid_columnconfigure(1, weight=1)

        ttk.Label(left_card, text="로그인", style="Title1.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w"
        )
        ttk.Separator(left_card).grid(
            row=1, column=0, columnspan=2, sticky="ew", pady=10
        )

        ttk.Label(left_card, text="아이디", style="Muted1.TLabel").grid(
            row=2,
            column=0,
            sticky="w",
            pady=(4, 2),
        )
        self.ent_id = ttk.Entry(left_card, textvariable=self.id_var)
        self.ent_id.grid(row=2, column=1, sticky="ew", pady=(4, 2))

        ttk.Label(left_card, text="비밀번호", style="Muted1.TLabel").grid(
            row=3, column=0, sticky="w", pady=(4, 2)
        )
        self.ent_pw = ttk.Entry(left_card, textvariable=self.pw_var, show="•")
        self.ent_pw.grid(row=3, column=1, sticky="ew", pady=(4, 2))

        btns = ttk.Frame(left_card, padding=0)
        btns.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        btns.grid_columnconfigure(0, weight=1)
        btns.grid_columnconfigure(1, weight=1)

        self.btn_login = ttk.Button(
            btns, text="로그인", command=self.on_login, style="Link.TButton"
        )
        self.btn_login.grid(row=0, column=0, sticky="nsew", padx=0, pady=0)
        self.btn_signup = ttk.Button(
            btns, text="회원가입", command=self.on_signup, style="Link.TButton"
        )
        self.btn_signup.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)

        # 상태/도움말
        self.lbl_status = ttk.Label(
            left_card,
            textvariable=self.msg_var,
            style="Muted.TLabel",
            wraplength=320,
            justify="left",
        )
        self.lbl_status.grid(row=5, column=0, columnspan=2, sticky="w", pady=(10, 0))

        # (우) 제어/대시보드 카드
        right_card = ttk.Frame(main, style="Card.TFrame", padding=20)
        right_card.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        right_card.grid_columnconfigure(0, weight=1)
        ttk.Label(right_card, text="실시간 암호화 제어", style="Title1.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        ttk.Separator(right_card).grid(row=1, column=0, sticky="ew", pady=10)

        # 토글/대시보드/학습
        ctl = ttk.Frame(right_card)
        ctl.grid(row=2, column=0, sticky="ew")
        ctl.grid_columnconfigure(0, weight=1)
        ctl.grid_columnconfigure(1, weight=1)
        ctl.grid_columnconfigure(2, weight=1)
        ctl.grid_columnconfigure(3, weight=1)  # ← 추가

        self.btn_toggle = ttk.Button(
            ctl,
            text="암호화 시작",
            command=self.on_toggle,
            # style="Accent.TButton",
            state=DISABLED,
        )
        self.btn_toggle.grid(row=0, column=0, sticky="ew", padx=(0, 8))

        self.btn_dash = ttk.Button(
            ctl, text="대시보드 열기", command=self.on_open_dashboard, state=DISABLED
        )
        self.btn_dash.grid(row=0, column=1, sticky="ew", padx=(0, 8))

        self.btn_learn = ttk.Button(
            ctl, text="패턴 학습 시작", command=self.on_toggle_learning, state=DISABLED
        )
        self.btn_learn.grid(row=0, column=2, sticky="ew", padx=(0, 8))

        # 기존 3개 버튼 아래에 추가
        self.btn_analyze = ttk.Button(
            ctl, text="학습 데이터 분석", command=self.on_analyze, state=DISABLED
        )
        self.btn_analyze.grid(row=0, column=3, sticky="ew")

        # 사용 팁
        tip = ttk.Label(
            right_card,
            text="TIP: 로그인 → 매핑 다운로드 → [암호화 시작].\n대시보드에서 실시간 로그/CPU/암호화 지연을 볼 수 있어요.",
            style="Muted.TLabel",
            justify="left",
        )
        tip.grid(row=3, column=0, sticky="w", pady=(12, 0))

        # 하단 상태바
        statusbar = ttk.Frame(shell, style="Status.TFrame", padding=(8, 6))
        statusbar.grid(row=2, column=0, sticky="ew", pady=(12, 0))
        statusbar.grid_columnconfigure(0, weight=1)
        ttk.Label(statusbar, text="© CapSecure", style="Status.TLabel").grid(
            row=0, column=1, sticky="e"
        )

    # -------- UX 헬퍼 --------
    def set_status(self, text: str):
        self.root.after(0, lambda: self.msg_var.set(text))

    def _ui_after_login(self):
        self.btn_toggle.config(state=NORMAL)
        self.btn_dash.config(state=NORMAL)
        self.btn_learn.config(state=NORMAL)
        if hasattr(self, "btn_analyze"):
            self.btn_analyze.config(state=NORMAL)  # ← 추가

        self.btn_login.config(text="로그아웃", command=self.on_logout, state=NORMAL)
        # 회원가입 버튼 비활성화
        self.btn_signup.config(state=DISABLED)

    # -------- 이벤트 핸들러 --------
    def on_signup(self):
        if SIGNUP_URL:
            import webbrowser

            webbrowser.open(SIGNUP_URL)
        self.set_status("브라우저에서 회원가입을 완료한 뒤, 이 창에서 로그인하세요.")

    def on_login(self):
        username = self.id_var.get().strip().lower()
        password = self.pw_var.get()
        if not username or not password:
            self.set_status("아이디/비밀번호를 입력하세요.")
            return
        self.btn_login.config(state=DISABLED)
        self.set_status("서버 로그인 중…")

        import threading

        threading.Thread(
            target=self._login_flow, args=(username, password), daemon=True
        ).start()

    def _login_flow(self, username, password):
        try:
            token = api_login(username, password)
            self._token = token
            self.set_status("매핑 다운로드 중…")
            mapping, version = api_get_ascii_map(token)
            self.mapping = mapping  # <-- [FIX] 매핑 저장

            # Hook/Dashboard 준비
            user_secret = hashlib.sha256(
                username.encode()
            ).digest()  # 예시: 서버에서 받아온 시크릿으로 교체
            salt = hashlib.sha256(str(version).encode()).digest()  # str()로 안전하게
            key = derive_session_key(user_secret, salt)
            encryptor = AESEncryptor(key)

            # 대시보드
            self.dashboard = DashboardServer(
                mapping_getter=lambda: getattr(
                    self, "mapping", {}
                ),  # <-- [FIX] 안전한 게터
                crypto_ms_getter=lambda: (
                    self.hook.last_crypto_ms if self.hook else 0.0
                ),  # <-- [FIX] 안전한 게터
            )
            self.dashboard.start()

            # 후킹
            self.hook = HookEngine(  # <-- [FIX] KeyHooker -> HookEngine
                self.mapping,
                encryptor,
                self.set_status,  # 콜백 전달
                dashboard=self.dashboard,
                api_token=self._token,  # <-- [FIX] 토큰 전달
            )
            self.set_status(f"로그인 완료. 매핑 v{version} 적용됨.")
            self.root.after(0, self._ui_after_login)
        except Exception as e:
            self.set_status(f"로그인 실패: {e}")
            self.root.after(0, lambda: self.btn_login.config(state=NORMAL))

    def on_logout(self):
        self.btn_login.config(state=DISABLED)
        try:
            # 학습 중이면 종료
            if getattr(self, "_learning", False):
                try:
                    self._pattern_client.stop_learning()
                except Exception:
                    pass
                self._learning = False
                self.btn_learn.config(text="패턴 학습 시작")

            # 후킹 중지
            if self.hook:
                try:
                    self.hook.stop()
                except Exception:
                    pass
            if self.dashboard:
                try:
                    self.dashboard.stop()
                except Exception:
                    pass

            # 토큰/핸들 정리
            self._token = None
            self.hook = None
            self.dashboard = None

            # 컨트롤 비활성화
            self.btn_toggle.config(state=DISABLED, text="암호화 시작")
            self.btn_dash.config(state=DISABLED)
            self.btn_learn.config(state=DISABLED)
            if hasattr(self, "btn_analyze"):
                self.btn_analyze.config(state=DISABLED)

            # 비밀번호 클리어
            try:
                self.pw_var.set("")
            except Exception:
                pass

            self.set_status("로그아웃 되었습니다.")

        finally:
            self.btn_login.config(text="로그인", command=self.on_login, state=NORMAL)
            # 회원가입 버튼 다시 활성화
            self.btn_signup.config(state=NORMAL)

    def on_open_dashboard(self):
        import webbrowser

        if self.dashboard:
            webbrowser.open(f"http://{self.dashboard.host}:{self.dashboard.port}")
            self.set_status("대시보드를 브라우저로 열었어요.")
        else:
            self.set_status("대시보드가 아직 준비되지 않았어요.")

    def on_toggle(self):
        if self._toggle_busy:
            return
        self._toggle_busy = True
        try:
            if self.hook and not self.hook._running:  # <-- [FIX] .running -> ._running
                self.hook.start()
                self.btn_toggle.config(text="암호화 중지")
                self.set_status("키 입력 암호화를 시작했어요.")
            elif self.hook and self.hook._running:  # <-- [FIX] .running -> ._running
                self.hook.stop()
                self.btn_toggle.config(text="암호화 시작")
                self.set_status("키 입력 암호화를 중지했어요.")
        finally:
            # 빠른 클릭 방지
            self.root.after(100, lambda: setattr(self, "_toggle_busy", False))

    def on_toggle_learning(self):
        # [FIX] PatternClient 대신 self.hook 사용
        if not self.hook:
            self.set_status("후킹이 준비되지 않았어요. 다시 로그인해 주세요.")
            return

        if not self._learning:
            try:
                # HookEngine에 내장된 학습 시작 메서드 호출
                self.hook.start_learning(policy="threshold", min_events=600)
                self._learning = True
                self.set_status("패턴 학습을 시작했어요.")
                self.btn_learn.config(text="학습 종료")
            except Exception as e:
                self.set_status(f"학습 시작 실패: {e}")
        else:
            try:
                # HookEngine에 내장된 학습 종료 메서드 호출
                self.hook.stop_learning()
                self.set_status("패턴 학습을 종료했어요.")
            except Exception as e:
                self.set_status(f"학습 종료 오류: {e}")
            finally:
                self._learning = False
                self.btn_learn.config(text="패턴 학습 시작")

    def on_analyze(self):
        if not self._token:
            self.set_status("분석을 위해 먼저 로그인하세요.")
            return
        self.btn_analyze.config(state=DISABLED)
        self.set_status("서버에 데이터 분석 요청 중…")

        def _run():
            try:
                r = requests.post(
                    f"{API_BASE}/api/pattern/analyze",
                    headers={"Authorization": f"Bearer {self._token}"},
                    timeout=60,
                )
                if r.status_code == 200:
                    msg = r.json().get("message", "분석 완료")
                    self.set_status(f"성공: {msg}")
                else:
                    try:
                        err = r.json().get("error", "")
                    except Exception:
                        err = ""
                    self.set_status(f"분석 실패: HTTP {r.status_code} {err}")
            except Exception as e:
                self.set_status(f"분석 요청 실패: {e}")
            finally:
                self.root.after(0, lambda: self.btn_analyze.config(state=NORMAL))

        threading.Thread(target=_run, daemon=True).start()

    def on_close(self):
        # 안전 종료
        try:
            if self._learning:
                self.on_toggle_learning()
            if self.hook:
                self.hook.stop()
            if self.dashboard:
                self.dashboard.push_close_signal()
                self.dashboard.stop()
        finally:
            self.root.destroy()

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    App().run()
