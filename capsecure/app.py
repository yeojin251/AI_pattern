# app.py — Capstone Secure Keyboard (GUI + 내장 대시보드)
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
API_BASE   = "http://127.0.0.1:5000"              # Flask 서버 주소
SIGNUP_URL = "http://127.0.0.1:5500/index.html"   # 회원가입 웹페이지 주소

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
    else if(data.type === "close") {
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
        self.clients = set()

        app = self.app  # 로컬 참조

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
        """모든 클라이언트에게 창을 닫으라는 신호를 보냅니다."""
        if self.loop and self.loop.is_running():
            async def _broadcast_close():
                message = json.dumps({"type": "close"})
                # asyncio.gather를 사용해 모든 전송 작업을 동시에 실행
                await asyncio.gather(
                    *[ws.send_text(message) for ws in self.clients],
                    return_exceptions=True  # 오류가 발생해도 계속 진행
                )

            # 다른 스레드(GUI)에서 비동기 함수를 안전하게 실행하고 끝날 때까지 기다림
            future = asyncio.run_coroutine_threadsafe(_broadcast_close(), self.loop)
            try:
                future.result(timeout=1.0)  # 최대 1초간 기다림
                print("닫기 신호 전송 완료.")
            except Exception as e:
                print(f"닫기 신호 전송 중 오류: {e}")

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


# ========= 후킹 엔진 ========= (대시보드 연동 추가)
class HookEngine:
    def __init__(self, mapping: dict, encryptor: AESEncryptor, ui_status_cb, dashboard: DashboardServer | None = None):
        self.mapping = mapping
        self.encryptor = encryptor
        self.ui_status_cb = ui_status_cb
        self.dashboard = dashboard
        self._listener = None
        self._running = False
        self.total_time = 0.0
        self.last_crypto_ms = 0.0

    def _on_press(self, key):
        try:
            ch = key.char
            if ch in self.mapping:
                remapped = self.mapping[ch]
                t0 = time.perf_counter()
                ct = self.encryptor.encrypt_byte(remapped.encode("utf-8"))
                self.last_crypto_ms = (time.perf_counter() - t0) * 1000.0
                self.total_time += self.last_crypto_ms
                # self.ui_status_cb(f"[입력] '{ch}' → '{remapped}' → ct={ct.hex()[:24]}…  {self.last_crypto_ms:.2f}ms")

                # 대시보드로 이벤트 푸시
                if self.dashboard:
                    self.dashboard.push_event(ch, remapped, ct.hex())
        except AttributeError:
            if key == keyboard.Key.esc:
                self.ui_status_cb("ESC 입력: 종료")
                return False

    def start(self):
        if self._running: return
        self._running = True
        self._listener = keyboard.Listener(on_press=self._on_press)
        self._listener.start()
        self.ui_status_cb("암호화 ON (ESC로 종료 가능)")

    def stop(self):
        if self._listener:
            self._listener.stop()
        self._running = False
        self.ui_status_cb("암호화 OFF")


# ========= GUI 앱 ========= (로그아웃 + 대시보드 연동)
class App:
    def __init__(self):
        self.root = Tk()
        self.root.title("KIM&JANG Secure Keyboard")
        self.root.geometry("350x220")
        self.root.resizable(False, False)

        # 1) 중앙 컨테이너: 창 전체를 차지
        self.center = Frame(self.root)
        self.center.pack(expand=True, fill="both")

        # 2) 실제 폼을 담을 프레임: 가운데에 고정
        self.form = Frame(self.center)
        self.form.place(relx=0.5, rely=0.5, anchor="center")

        # ===== 여기부터는 기존 위젯들의 부모를 self.root -> self.form 으로만 변경 =====
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

        self.btn_login.grid(row=3, column=0, columnspan=2, padx=20, pady=(8,4))
        self.btn_signup.grid(row=4, column=0, padx=(20,6), pady=(0,10), sticky="e")
        self.btn_logout.grid(row=4, column=1, padx=(6,20),  pady=(0,10), sticky="w")

        self.lbl_msg = Label(self.form, textvariable=self.msg_var, fg="#444", wraplength=380, justify="left")
        self.lbl_msg.grid(row=5, column=0, columnspan=2, padx=20, pady=(4,12))

        # 나머지 로직(후킹/대시보드/버튼 핸들러 등)은 그대로
        self.hook = None
        self.dashboard = None
        self._token = None
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

        # 네트워크 작업은 스레드로 (UI 멈춤 방지)
        threading.Thread(target=self._login_flow, args=(username, password), daemon=True).start()

    def _login_flow(self, username, password):
        try:
            token = api_login(username, password)
            self._token = token
            self.set_status("매핑 다운로드 중…")
            mapping, version = api_get_ascii_map(token)

            # 세션키 파생 (실서비스는 서버가 준 salt/map_hash 사용 권장)
            user_secret = secrets.token_bytes(32)
            salt        = secrets.token_bytes(32)
            session_key = derive_session_key(user_secret, salt)
            encryptor   = AESEncryptor(session_key)

            # 대시보드 서버 시작 (매핑/crypto_ms를 콜백으로 제공)
            def get_mapping():
                return mapping
            def get_crypto_ms():
                return self.hook.last_crypto_ms if self.hook else 0.0
            self.dashboard = DashboardServer(lambda: mapping, get_crypto_ms)
            self.dashboard.start()

            # 후킹 시작 (대시보드에 이벤트 푸시하도록 연결)
            self.hook = HookEngine(mapping, encryptor, self.set_status, dashboard=self.dashboard)
            self.hook.start()

            self.set_status(f"로그인 성공! 매핑 v{version} 적용. 키 입력을 암호화합니다. (ESC 종료)")
            # 로그아웃 버튼 활성화
            self.root.after(0, lambda: self.btn_logout.config(state=NORMAL))
        except Exception as e:
            self.set_status(f"에러: {e}")
            self.root.after(0, lambda: self.btn_login.config(state=NORMAL))

    # 로그아웃 (후킹/대시보드 정지 + 입력값/버튼 초기화)
    def on_logout(self):
        try:
            # 1. 먼저 닫기 신호를 보냅니다. (이 함수는 완료될 때까지 기다립니다)
            if self.dashboard:
                self.dashboard.push_close_signal()
            
            # 2. 키보드 후킹을 중지합니다.
            if self.hook:
                self.hook.stop()
                self.hook = None

            # 3. 마지막으로 대시보드 서버를 중지합니다.
            if self.dashboard:
                self.dashboard.stop()
                self.dashboard = None
        finally:
            # UI 초기화
            self._token = None
            self.id_var.set("")
            self.pw_var.set("")
            self.btn_login.config(state=NORMAL)
            self.btn_logout.config(state=DISABLED)
            self.set_status("로그아웃 되었습니다. 다시 로그인하세요.")

    # 창 닫힐 때 정리
    def on_close(self):
        try:
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