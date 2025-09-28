# app.py — Capstone Secure Keyboard (GUI + 대시보드 + 패턴학습 토글/디바운스 + prev_code 수집)
# 요구 패키지: requests, pynput, cryptography, fastapi, uvicorn, psutil
# 설치: pip install requests pynput cryptography fastapi uvicorn psutil

import threading
import asyncio
import time
import secrets
import hmac
import hashlib
import requests
import webbrowser
from tkinter import Tk, Label, Entry, Button, StringVar, DISABLED, NORMAL, Frame
from pynput import keyboard
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ==== 대시보드용 추가 의존성 ====
import json
import psutil
from typing import Set
from fastapi import FastAPI, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn

# ========= 설정 =========
API_BASE   = "http://127.0.0.1:5000"              # Flask 서버 주소 (server.py)
SIGNUP_URL = "http://127.0.0.1:5500/index.html"   # 회원가입 웹페이지 주소 (있다면)

DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 8765

# ========= 서버 API =========
def api_login(username: str, password: str) -> str:
    r = requests.post(f"{API_BASE}/api/login",
                      json={"username": username, "password": password},
                      timeout=10)
    if r.status_code != 200:
        try:
            msg = r.json().get("error")
        except Exception:
            msg = None
        raise RuntimeError(msg or f"로그인 실패 (HTTP {r.status_code})")
    return r.json()["token"]

def api_get_ascii_map(token: str):
    r = requests.get(f"{API_BASE}/api/me/ascii-map",
                     headers={"Authorization": f"Bearer {token}"},
                     timeout=10)
    if r.status_code != 200:
        try:
            msg = r.json().get("error")
        except Exception:
            msg = None
        raise RuntimeError(msg or f"매핑 조회 실패 (HTTP {r.status_code})")
    data = r.json()
    mapping = { chr(int(k)): chr(v) for k, v in data["asciiMap"].items() }
    return mapping, data["version"]

# ========= 세션키 파생 =========
def derive_session_key(user_secret: bytes, salt: bytes) -> bytes:
    return hmac.new(user_secret, salt, hashlib.sha256).digest()  # 32B AES-256

# ========= 암호화기 =========
class AESEncryptor:
    def __init__(self, key: bytes):
        assert len(key) == 32, "세션키 길이가 32바이트가 아닙니다."
        self.key = key
        self.aesgcm = AESGCM(self.key)
        self.nonce = secrets.token_bytes(12)  # 데모용 (실서비스는 per-message 권장)

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
  }
  else if (data.type === "close") {
    window.close();
  }
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
    """Tk GUI 앱 내부에서 실행되는 경량 대시보드 서버 (FastAPI+WebSocket)."""
    def __init__(self, mapping_getter, crypto_ms_getter):
        self.mapping_getter = mapping_getter  # callable -> dict
        self.crypto_ms_getter = crypto_ms_getter  # callable -> float
        self.loop: asyncio.AbstractEventLoop | None = None
        self.thread: threading.Thread | None = None
        self.app: FastAPI | None = None
        self.server: uvicorn.Server | None = None
        self.event_q: asyncio.Queue | None = None
        self.clients: Set[WebSocket] = set()
        self.proc = psutil.Process()
        self.proc.cpu_percent(interval=None)

    def push_event(self, ch: str, remapped: str, cipher_hex: str):
        """키 이벤트를 대시보드로 전달 (안전하게 루프 스레드로)."""
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
            return  # 이미 실행 중
        self.thread = threading.Thread(target=self._run, args=(host, port), daemon=True)
        self.thread.start()
        # 바로 브라우저 오픈
        webbrowser.open(f"http://{host}:{port}/")

    def _run(self, host: str, port: int):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.event_q = asyncio.Queue()
        self.app = FastAPI()
               # 로컬 참조
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
            except Exception:
                pass
            finally:
                self.clients.discard(ws)

        async def broadcaster_task():
            last_cpu_push = 0.0
            while True:
                # 1) 키 이벤트 브로드캐스트 (즉시)
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

                # 2) CPU / crypto_ms 0.5초 간격 전송
                now = time.time()
                if now - last_cpu_push >= 0.5:
                    cpu_proc = self.proc.cpu_percent(interval=None)
                    payload = {
                        "type": "cpu",
                        "proc_cpu": cpu_proc,
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

        config = uvicorn.Config(app, host=host, port=port, log_level="warning", loop="asyncio")
        self.server = uvicorn.Server(config)
        task_broadcaster = self.loop.create_task(broadcaster_task())
        try:
            self.loop.run_until_complete(self.server.serve())
        finally:
            task_broadcaster.cancel()
            try:
                self.loop.run_until_complete(task_broadcaster)
            except Exception:
                pass

    def push_close_signal(self):
        if self.loop and self.loop.is_running():
            async def _broadcast_close():
                msg = json.dumps({"type": "close"})
                await asyncio.gather(
                    *[ws.send_text(msg) for ws in list(self.clients)],
                    return_exceptions=True
                )
            fut = asyncio.run_coroutine_threadsafe(_broadcast_close(), self.loop)
            try:
                fut.result(timeout=1.0)
            except Exception:
                pass

    def stop(self):
        """서버를 안전하게 종료합니다."""
        if self.loop and self.server:
            # should_exit 플래그를 설정하여 uvicorn 루프가 자연스럽게 종료되도록 함
            self.loop.call_soon_threadsafe(setattr, self.server, 'should_exit', True)
        if self.thread:
            self.thread.join(timeout=2.0) # 스레드가 종료될 때까지 최대 2초 기다림
        # 리소스 정리
        self.thread = None
        self.loop = None
        self.app = None
        self.server = None
        self.clients.clear()

# ========= 후킹 엔진 ========= (대시보드 연동 + 패턴학습 수집 + prev_code)
class HookEngine:
    def __init__(self, mapping: dict, encryptor: AESEncryptor, ui_status_cb,
                 dashboard: DashboardServer | None = None,
                 api_base: str = API_BASE, api_token: str | None = None):
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

        # 학습 수집 상태
        self.learn_active = False
        self.learn_session_id = None
        self.learn_buf = []
        self.learn_lock = threading.Lock()
        self.down_map = {}       # code -> (t_down_mono, ts_down_epoch_ms)
        self.last_up_mono = None
        self.last_up_code = None

        self._flush_thread = None
        self._flush_stop = threading.Event()

    # ---- 유틸 ----
    def _code_of(self, key):
        try:
            return f"Char.{key.char}"
        except AttributeError:
            try:
                return f"Key.{key.name}"
            except Exception:
                return str(key)

    def _headers(self):
        return {"Authorization": f"Bearer {self.api_token}", "Content-Type": "application/json"} if self.api_token else {"Content-Type":"application/json"}

    # ---- 서버 통신 (학습) ----
    def start_learning(self, min_events=600, policy="threshold"):
        if self.learn_active:
            return
        if not self.api_token:
            raise RuntimeError("토큰 없음: 로그인 후 사용하세요.")
        r = requests.post(f"{self.api_base}/api/pattern/start",
                          headers=self._headers(),
                          json={"min_events": int(min_events), "policy": policy}, timeout=10)
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
            requests.post(f"{self.api_base}/api/pattern/stop",
                          headers=self._headers(), json={"session_id": self.learn_session_id}, timeout=5)
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

    def _flush_once(self, force: bool=False):
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
            r = requests.post(f"{self.api_base}/api/pattern/collect",
                              headers=self._headers(),
                              json={"session_id": self.learn_session_id, "samples": batch},
                              timeout=10)
            j = r.json()
            if j.get("stop"):
                # 서버 임계치 도달 → 자동 정지
                self.learn_active = False
                self.learn_session_id = None
                self.ui_status_cb(f"패턴 학습 자동 종료(총 {j.get('total',0)} 이벤트).")
        except Exception as e:
            self.ui_status_cb(f"수집 전송 오류: {e}")

    # ---- 키 이벤트 ----
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
        if self.learn_active:
            code = self._code_of(key)
            if code not in self.down_map:
                # mono: perf_counter, epoch_ms: time.time()*1000
                self.down_map[code] = (time.perf_counter(), round(time.time()*1000, 3))

        # ESC -> 전체 후킹 종료(암호화)
        try:
            if key == keyboard.Key.esc:
                self.ui_status_cb("ESC 입력: 종료")
                return False
        except Exception:
            pass

    def _on_release(self, key):
        if not self.learn_active:
            return
        code = self._code_of(key)
        t_up_mono = time.perf_counter()
        ts_up_epoch_ms = round(time.time()*1000, 3)
        if code in self.down_map:
            t_down_mono, ts_down_epoch_ms = self.down_map.pop(code)
            dwell = (t_up_mono - t_down_mono) * 1000.0  # ms
            flight = None if self.last_up_mono is None else (t_down_mono - self.last_up_mono) * 1000.0
            try:
                kchar = key.char
            except AttributeError:
                kchar = ""
            sample = {
                "ts_down": ts_down_epoch_ms,
                "ts_up":   ts_up_epoch_ms,
                "dwell":   round(dwell, 3),
                "flight":  (None if flight is None else round(flight, 3)),
                "code":    code,
                "prev_code": (self.last_up_code or ""),
                "key":     kchar or ""
            }
            with self.learn_lock:
                self.learn_buf.append(sample)
            self.last_up_mono = t_up_mono
            self.last_up_code = code

            # 버퍼가 크면 즉시 전송
            if len(self.learn_buf) >= 120:
                self._flush_once(force=False)

    def start(self):
        if self._running: return
        self._running = True
        self._listener = keyboard.Listener(on_press=self._on_press, on_release=self._on_release)
        self._listener.start()
        self.ui_status_cb("암호화 ON (ESC로 종료 가능)")

    def stop(self):
        # 학습 중이면 먼저 정지
        if self.learn_active:
            try: self.stop_learning()
            except: pass
        if self._listener:
            self._listener.stop()
        self._running = False
        self.ui_status_cb("암호화 OFF")

# ========= GUI 앱 ========= (로그인/로그아웃 + 패턴 학습 버튼 디바운스)
class App:
    def __init__(self):
        self.root = Tk()
        self.root.title("KIM&JANG Secure Keyboard")
        self.root.geometry("350x240")
        self.root.resizable(False, False)

        # 1) 중앙 컨테이너
        self.center = Frame(self.root)
        self.center.pack(expand=True, fill="both")

        # 2) 폼 프레임
        self.form = Frame(self.center)
        self.form.place(relx=0.5, rely=0.5, anchor="center")

        Label(self.form, text="로그인", font=("Malgun Gothic", 12, "bold"))\
            .grid(row=0, column=0, columnspan=2, pady=(10, 4))

        self.id_var  = StringVar()
        self.pw_var  = StringVar()
        self.msg_var = StringVar(value="회원가입 후 아이디/비밀번호로 로그인하세요.")

        self.id_entry = Entry(self.form, textvariable=self.id_var, width=34)
        self.pw_entry = Entry(self.form, textvariable=self.pw_var, width=34, show="*")

        self.id_entry.grid(row=1, column=0, columnspan=2, padx=20, pady=6)
        self.pw_entry.grid(row=2, column=0, columnspan=2, padx=20, pady=6)

        self.btn_login   = Button(self.form, text="로그인",   width=32, command=self.on_login)
        self.btn_signup  = Button(self.form, text="회원가입", width=16, command=self.on_signup)
        self.btn_logout  = Button(self.form, text="로그아웃", width=16, command=self.on_logout, state=DISABLED)
        self.btn_learn   = Button(self.form, text="패턴 학습 시작", width=32, state=DISABLED, command=self.on_toggle_learn)

        self.btn_login.grid(row=3, column=0, columnspan=2, padx=20, pady=(8,4))
        self.btn_signup.grid(row=4, column=0, padx=(20,6), pady=(0,8), sticky="e")
        self.btn_logout.grid(row=4, column=1, padx=(6,20),  pady=(0,8), sticky="w")
        self.btn_learn.grid(row=5, column=0, columnspan=2, padx=20, pady=(0,8))

        self.lbl_msg = Label(self.form, textvariable=self.msg_var, fg="#444", wraplength=380, justify="left")
        self.lbl_msg.grid(row=6, column=0, columnspan=2, padx=20, pady=(2,10))

        # 나머지 로직
        self.hook = None
        self.dashboard = None
        self._token = None
        self._toggle_busy = False
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # UI 메시지 업데이트
    def set_status(self, text: str):
        self.root.after(0, lambda: self.msg_var.set(text))

    # 회원가입 버튼 → 브라우저로 회원가입 페이지 오픈
    def on_signup(self):
        webbrowser.open(SIGNUP_URL)
        self.set_status("브라우저에서 회원가입을 완료한 뒤, 이 창에서 로그인하세요.")

    # 로그인 버튼
    def on_login(self):
        username = self.id_var.get().strip().lower()
        password = self.pw_var.get()
        if not username or not password:
            self.set_status("아이디/비밀번호를 입력하세요.")
            return
        self.btn_login.config(state=DISABLED)
        self.set_status("서버 로그인 중…")
        threading.Thread(target=self._login_flow, args=(username, password), daemon=True).start()

    def _login_flow(self, username, password):
        try:
            token = api_login(username, password)
            self._token = token
            self.set_status("매핑 다운로드 중…")
            mapping, version = api_get_ascii_map(token)

            # 세션키 파생 (실서비스는 서버 salt/map_hash 권장)
            user_secret = secrets.token_bytes(32)
            salt        = secrets.token_bytes(32)
            session_key = derive_session_key(user_secret, salt)
            encryptor   = AESEncryptor(session_key)

            # 대시보드 서버 시작 (매핑/crypto_ms 콜백)
            def get_crypto_ms():
                return self.hook.last_crypto_ms if self.hook else 0.0
            self.dashboard = DashboardServer(lambda: mapping, get_crypto_ms)
            self.dashboard.start()

            # 후킹 시작 (대시보드에 이벤트 푸시)
            self.hook = HookEngine(mapping, encryptor, self.set_status,
                                   dashboard=self.dashboard, api_base=API_BASE, api_token=token)
            self.hook.start()

            self.set_status(f"로그인 성공! 매핑 v{version} 적용. 키 입력을 암호화합니다. (ESC 종료)")
            # 버튼 활성화
            self.root.after(0, lambda: (self.btn_logout.config(state=NORMAL),
                                        self.btn_learn.config(state=NORMAL)))
        except Exception as e:
            self.set_status(f"에러: {e}")
            self.root.after(0, lambda: self.btn_login.config(state=NORMAL))

    # 패턴 학습 토글(디바운스)
    def on_toggle_learn(self):
        if not self.hook:
            self.set_status("로그인 후 사용하세요.")
            return
        if self._toggle_busy:
            return
        self._toggle_busy = True
        self.btn_learn.config(state=DISABLED)
        self.set_status("처리 중…")

        def _run():
            try:
                if self.hook.learn_active:
                    self.hook.stop_learning()
                    self.set_status("패턴 학습 정지됨.")
                    self.root.after(0, lambda: self.btn_learn.config(text="패턴 학습 시작"))
                else:
                    # 임계치(이벤트 수) 조절 가능: min_events=600 → 빠르게 테스트하려면 300
                    self.hook.start_learning(min_events=600, policy="threshold")
                    self.set_status("패턴 학습 수집 시작… 타이핑해주세요.")
                    self.root.after(0, lambda: self.btn_learn.config(text="패턴 학습 정지"))
            except Exception as e:
                self.set_status(f"패턴 학습 오류: {e}")
            finally:
                self._toggle_busy = False
                self.root.after(0, lambda: self.btn_learn.config(state=NORMAL))
        threading.Thread(target=_run, daemon=True).start()

    # 로그아웃
    def on_logout(self):
        try:
            if self.dashboard:
                try: self.dashboard.push_close_signal()
                except: pass
            if self.hook and self.hook.learn_active:
                try: self.hook.stop_learning()
                except: pass
            if self.hook:
                self.hook.stop()
                self.hook = None
            if self.dashboard:
                self.dashboard.stop()
                self.dashboard = None
        finally:
            # UI 초기화
            self._token = None
            self._toggle_busy = False
            self.id_var.set("")
            self.pw_var.set("")
            self.btn_login.config(state=NORMAL)
            self.btn_logout.config(state=DISABLED)
            self.btn_learn.config(state=DISABLED, text="패턴 학습 시작")
            self.set_status("로그아웃 되었습니다. 다시 로그인하세요.")

    # 창 닫힐 때 정리
    def on_close(self):
        try:
            if self.hook and self.hook.learn_active:
                try: self.hook.stop_learning()
                except: pass
            if self.hook:
                self.hook.stop()
            if self.dashboard:
                self.dashboard.stop()
        finally:
            self.root.destroy()

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    App().run()
