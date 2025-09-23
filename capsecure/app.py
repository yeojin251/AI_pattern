# app.py — Capstone Secure Keyboard (GUI + 내장 대시보드 + 패턴 학습)
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
from fastapi import FastAPI, WebSocket, Request
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn
import os


# ========= 설정 =========
API_BASE = "http://127.0.0.1:5000"  # Flask 서버 주소
SIGNUP_URL = "http://127.0.0.1:5500/index.html"  # 회원가입 웹페이지 주소

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
        assert len(key) == 32, "세션키 길이가 32바이트가 아닙니다."
        self.key = key
        self.aesgcm = AESGCM(self.key)
        self.nonce = secrets.token_bytes(12)  # 데모용 (실서비스는 per-message 권장)

    def encrypt_byte(self, b: bytes) -> bytes:
        return self.aesgcm.encrypt(self.nonce, b, None)


# ========= 내장 대시보드 및 학습 페이지 HTML =========
DASHBOARD_HTML = """
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>Keyboard Security Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: system-ui; margin: 24px; background-color: #f9f9f9; }
        h2, h3 { color: #333; }
        .row { display: flex; gap: 24px; margin-bottom: 24px; }
        .card { background-color: white; border-radius: 8px; padding: 16px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        table { border-collapse: collapse; width: 100%; }
        th, td { border-bottom: 1px solid #eee; padding: 8px 10px; text-align: left; }
        th { background-color: #f7f7f7; }
        small { color: #777; }
        .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(100px, 1fr)); gap: 8px; }
        .cell { border: 1px solid #ddd; padding: 8px; text-align: center; border-radius: 8px; background-color: #fafafa; }
        .button { display: inline-block; padding: 12px 18px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px; text-align: center; font-weight: bold; transition: background-color 0.2s; }
        .button:hover { background-color: #0056b3; }
    </style>
</head>
<body>
    <h2>실시간 키보드 보안 대시보드</h2>
    <div class="row">
        <div style="flex:2" class="card">
            <h3>입력 &rarr; 매핑 &rarr; 암호문</h3>
            <table id="log">
                <thead>
                    <tr><th>시간</th><th>입력</th><th>매핑</th><th>암호문(hex, 앞부분)</th></tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>
        <div style="flex:1">
            <div class="card" style="margin-bottom: 24px;">
                <h3>패턴 학습</h3>
                <p style="color:#555;">정확한 사용자 인증을 위해<br>주기적으로 타이핑 패턴을 학습시켜주세요.</p>
                <a href="/learn" class="button">패턴 학습 페이지로 이동</a>
            </div>
            <div class="card">
                <h3>CPU 사용률(%)</h3>
                <canvas id="cpuChart"></canvas>
                <div id="cryptoMs" style="margin-top:8px;color:#555"></div>
                <small>프로세스 전체 CPU 사용률. 입력 시 암호화 구간(ms)이 갱신됩니다.</small>
            </div>
        </div>
    </div>
    <div class="card">
        <h3>나의 ASCII 재정의 표</h3>
        <div id="mapGrid" class="grid"></div>
    </div>

    <script>
        const tbody = document.querySelector("#log tbody");
        const cpuCtx = document.getElementById('cpuChart').getContext('2d');
        const cpuData = { labels: [], datasets: [{ label: 'Process CPU %', data: [], borderColor: '#007bff', tension: 0.1, fill: false }] };
        const cpuChart = new Chart(cpuCtx, { type: 'line', data: cpuData, options: { animation: false, responsive: true, scales: { y: { min: 0, max: 30 } } } });
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
            document.getElementById("cryptoMs").textContent = `최근 암호화 구간: ${data.crypto_ms.toFixed(3)} ms`;
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
</body>
</html>
"""

LEARN_HTML = """
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>사용자 패턴 학습</title>
    <style>
        body { font-family: system-ui; margin: 24px; background-color: #f9f9f9; display: flex; justify-content: center; }
        .container { background-color: white; border-radius: 8px; padding: 24px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); max-width: 800px; width: 100%; }
        h2 { color: #333; }
        #sentence { background-color: #eee; padding: 16px; border-radius: 5px; margin: 16px 0; font-size: 1.1em; line-height: 1.6; }
        #typing-area { width: 100%; height: 150px; font-size: 1.1em; padding: 10px; border: 1px solid #ccc; border-radius: 5px; box-sizing: border-box; }
        .button-group { margin-top: 16px; display: flex; gap: 10px; }
        .button { display: inline-block; padding: 12px 18px; border: none; color: white; text-decoration: none; border-radius: 5px; text-align: center; cursor: pointer; font-weight: bold; transition: background-color 0.2s; }
        .primary { background-color: #28a745; }
        .primary:hover { background-color: #218838; }
        .secondary { background-color: #6c757d; }
        .secondary:hover { background-color: #5a6268; }
        #status { margin-top: 16px; font-weight: bold; color: #007bff; }
    </style>
</head>
<body>
    <div class="container">
        <h2>사용자 패턴 학습</h2>
        <p>정확한 인증을 위해, 아래 제시문을 최대한 평소 타이핑 습관대로 입력해주세요.</p>
        <p id="sentence">The quick brown fox jumps over the lazy dog. 다람쥐 헌 쳇바퀴에 타고파.</p>
        <textarea id="typing-area" placeholder="여기에 제시문을 입력하세요..."></textarea>
        
        <div class="button-group">
            <button id="save-btn" class="button primary">학습 완료 및 저장</button>
            <a href="/" class="button secondary">대시보드로 돌아가기</a>
        </div>
        
        <p id="status">학습을 시작하세요.</p>
    </div>

    <script>
        const textarea = document.getElementById('typing-area');
        const saveBtn = document.getElementById('save-btn');
        const statusEl = document.getElementById('status');
        
        let keyEvents = [];

        textarea.addEventListener('keydown', (e) => {
            if (e.key.length > 1 && !['Backspace', 'Enter', ' '].includes(e.key)) return;
            keyEvents.push({ 
                event_type: 'down', 
                key: e.key, 
                code: e.code, 
                timestamp: performance.now() 
            });
            statusEl.textContent = `총 ${keyEvents.length} 개의 키 이벤트가 수집되었습니다.`;
        });

        textarea.addEventListener('keyup', (e) => {
            if (e.key.length > 1 && !['Backspace', 'Enter', ' '].includes(e.key)) return;
            keyEvents.push({ 
                event_type: 'up', 
                key: e.key, 
                code: e.code, 
                timestamp: performance.now() 
            });
        });

        saveBtn.addEventListener('click', async () => {
            if (keyEvents.length < 20) {
                statusEl.textContent = '오류: 최소 20개 이상의 키 이벤트가 필요합니다.';
                statusEl.style.color = 'red';
                return;
            }
            
            statusEl.textContent = '서버로 데이터를 전송하고 있습니다...';
            statusEl.style.color = '#007bff';

            try {
                const response = await fetch('/save_pattern', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ events: keyEvents, sentence: document.getElementById('sentence').textContent })
                });

                if (response.ok) {
                    const result = await response.json();
                    statusEl.textContent = `✅ 저장 완료! 총 ${result.event_count}개의 이벤트가 성공적으로 저장되었습니다.`;
                    statusEl.style.color = 'green';
                    keyEvents = [];
                    textarea.value = '';
                } else {
                    throw new Error('Server responded with an error');
                }
            } catch (error) {
                statusEl.textContent = '❌ 오류 발생: 데이터를 저장하는 데 실패했습니다.';
                statusEl.style.color = 'red';
                console.error("Error saving pattern:", error);
            }
        });
    </script>
</body>
</html>
"""


class DashboardServer:
    """Tk GUI 앱 내부에서 실행되는 경량 대시보드 서버 (FastAPI+WebSocket)."""

    def __init__(self, mapping_getter, crypto_ms_getter):
        self.mapping_getter = mapping_getter
        self.crypto_ms_getter = crypto_ms_getter
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
            return
        self.thread = threading.Thread(target=self._run, args=(host, port), daemon=True)
        self.thread.start()
        webbrowser.open(f"http://{host}:{port}/")

    def _run(self, host: str, port: int):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.event_q = asyncio.Queue()
        self.app = FastAPI()
        self.clients = set()

        app = self.app

        @app.get("/")
        def index():
            return HTMLResponse(DASHBOARD_HTML)

        # ===== 신규: 패턴 학습 페이지 라우트 =====
        @app.get("/learn")
        def learn_page():
            return HTMLResponse(LEARN_HTML)

        # ===== 신규: 패턴 데이터 저장 라우트 =====
        @app.post("/save_pattern")
        async def save_pattern_data(request: Request):
            try:
                data = await request.json()
                event_count = len(data.get("events", []))
                file_path = "pattern_data.json"

                all_data = []
                if os.path.exists(file_path):
                    with open(file_path, "r", encoding="utf-8") as f:
                        try:
                            all_data = json.load(f)
                        except json.JSONDecodeError:
                            all_data = []  # 파일이 비어있거나 깨져있을 경우

                session_data = {
                    "session_id": int(time.time()),
                    "sentence": data.get("sentence"),
                    "events": data.get("events"),
                }
                all_data.append(session_data)

                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(all_data, f, ensure_ascii=False, indent=2)

                print(f"패턴 데이터 저장 완료. 이벤트 수: {event_count}")
                return JSONResponse({"status": "success", "event_count": event_count})

            except Exception as e:
                print(f"패턴 저장 오류: {e}")
                return JSONResponse(
                    {"status": "error", "message": str(e)}, status_code=500
                )

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
                    await asyncio.sleep(1.0)  # 연결 유지
            finally:
                self.clients.discard(ws)

        async def broadcaster_task():
            last_cpu_push = 0.0
            while True:
                try:
                    ev = await asyncio.wait_for(self.event_q.get(), timeout=0.2)
                    await asyncio.gather(
                        *[ws.send_text(json.dumps(ev)) for ws in self.clients],
                        return_exceptions=True,
                    )
                except asyncio.TimeoutError:
                    pass

                now = time.time()
                if now - last_cpu_push >= 0.5:
                    cpu_proc = self.proc.cpu_percent(interval=None)
                    payload = {
                        "type": "cpu",
                        "proc_cpu": cpu_proc,
                        "crypto_ms": float(self.crypto_ms_getter() or 0.0),
                    }
                    await asyncio.gather(
                        *[ws.send_text(json.dumps(payload)) for ws in self.clients],
                        return_exceptions=True,
                    )
                    last_cpu_push = now

        config = uvicorn.Config(
            app, host=host, port=port, log_level="warning", loop="asyncio"
        )
        self.server = uvicorn.Server(config)
        task_broadcaster = self.loop.create_task(broadcaster_task())
        try:
            self.loop.run_until_complete(self.server.serve())
        finally:
            task_broadcaster.cancel()

    def push_close_signal(self):
        if self.loop and self.loop.is_running():

            async def _broadcast_close():
                await asyncio.gather(
                    *[
                        ws.send_text(json.dumps({"type": "close"}))
                        for ws in self.clients
                    ],
                    return_exceptions=True,
                )

            future = asyncio.run_coroutine_threadsafe(_broadcast_close(), self.loop)
            try:
                future.result(timeout=1.0)
                print("닫기 신호 전송 완료.")
            except Exception as e:
                print(f"닫기 신호 전송 중 오류: {e}")

    def stop(self):
        if self.loop and self.server:
            self.loop.call_soon_threadsafe(setattr, self.server, "should_exit", True)
        if self.thread:
            self.thread.join(timeout=2.0)
        self.thread = None
        self.loop = None


# ========= 후킹 엔진 ========= (기존과 동일)
class HookEngine:
    def __init__(
        self,
        mapping: dict,
        encryptor: AESEncryptor,
        ui_status_cb,
        dashboard: DashboardServer | None = None,
    ):
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
                if self.dashboard:
                    self.dashboard.push_event(ch, remapped, ct.hex())
        except AttributeError:
            if key == keyboard.Key.esc:
                self.ui_status_cb("ESC 입력: 종료")
                return False

    def start(self):
        if self._running:
            return
        self._running = True
        self._listener = keyboard.Listener(on_press=self._on_press)
        self._listener.start()
        self.ui_status_cb("암호화 ON (ESC로 종료 가능)")

    def stop(self):
        if self._listener:
            self._listener.stop()
        self._running = False
        self.ui_status_cb("암호화 OFF")


# ========= GUI 앱 ========= (기존과 거의 동일)
class App:
    def __init__(self):
        self.root = Tk()
        self.root.title("KIM&JANG Secure Keyboard")
        self.root.geometry("350x220")
        self.root.resizable(False, False)

        self.center = Frame(self.root)
        self.center.pack(expand=True, fill="both")

        self.form = Frame(self.center)
        self.form.place(relx=0.5, rely=0.5, anchor="center")

        Label(self.form, text="로그인", font=("Malgun Gothic", 12, "bold")).grid(
            row=0, column=0, columnspan=2, pady=(10, 4)
        )

        self.id_var = StringVar()
        self.pw_var = StringVar()
        self.msg_var = StringVar(value="회원가입 후 아이디/비밀번호로 로그인하세요.")

        self.id_entry = Entry(self.form, textvariable=self.id_var, width=34)
        self.pw_entry = Entry(self.form, textvariable=self.pw_var, width=34, show="*")

        self.id_entry.grid(row=1, column=0, columnspan=2, padx=20, pady=6)
        self.pw_entry.grid(row=2, column=0, columnspan=2, padx=20, pady=6)

        self.btn_login = Button(
            self.form, text="로그인", width=32, command=self.on_login
        )
        self.btn_signup = Button(
            self.form, text="회원가입", width=16, command=self.on_signup
        )
        self.btn_logout = Button(
            self.form, text="로그아웃", width=16, command=self.on_logout, state=DISABLED
        )

        self.btn_login.grid(row=3, column=0, columnspan=2, padx=20, pady=(8, 4))
        self.btn_signup.grid(row=4, column=0, padx=(20, 6), pady=(0, 10), sticky="e")
        self.btn_logout.grid(row=4, column=1, padx=(6, 20), pady=(0, 10), sticky="w")

        self.lbl_msg = Label(
            self.form,
            textvariable=self.msg_var,
            fg="#444",
            wraplength=380,
            justify="left",
        )
        self.lbl_msg.grid(row=5, column=0, columnspan=2, padx=20, pady=(4, 12))

        self.hook = None
        self.dashboard = None
        self._token = None
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def set_status(self, text: str):
        self.root.after(0, lambda: self.msg_var.set(text))

    def on_signup(self):
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
        threading.Thread(
            target=self._login_flow, args=(username, password), daemon=True
        ).start()

    def _login_flow(self, username, password):
        try:
            token = api_login(username, password)
            self._token = token
            self.set_status("매핑 다운로드 중…")
            mapping, version = api_get_ascii_map(token)

            user_secret = secrets.token_bytes(32)
            salt = secrets.token_bytes(32)
            session_key = derive_session_key(user_secret, salt)
            encryptor = AESEncryptor(session_key)

            def get_crypto_ms():
                return self.hook.last_crypto_ms if self.hook else 0.0

            self.dashboard = DashboardServer(lambda: mapping, get_crypto_ms)
            self.dashboard.start()

            self.hook = HookEngine(
                mapping, encryptor, self.set_status, dashboard=self.dashboard
            )
            self.hook.start()

            self.set_status(
                f"로그인 성공! 매핑 v{version} 적용. 키 입력을 암호화합니다."
            )
            self.root.after(0, lambda: self.btn_logout.config(state=NORMAL))
        except Exception as e:
            self.set_status(f"에러: {e}")
            self.root.after(0, lambda: self.btn_login.config(state=NORMAL))

    def on_logout(self):
        try:
            if self.dashboard:
                self.dashboard.push_close_signal()
            if self.hook:
                self.hook.stop()
            if self.dashboard:
                self.dashboard.stop()
        finally:
            self.hook = None
            self.dashboard = None
            self._token = None
            self.id_var.set("")
            self.pw_var.set("")
            self.btn_login.config(state=NORMAL)
            self.btn_logout.config(state=DISABLED)
            self.set_status("로그아웃 되었습니다. 다시 로그인하세요.")

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
