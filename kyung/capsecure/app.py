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

# ========= 설정 =========
API_BASE   = "http://127.0.0.1:5000"            # Flask 서버 주소 (server.py)
SIGNUP_URL = "http://127.0.0.1:5500/index.html" # 회원가입 페이지 (없으면 빈 문자열로 두세요)

DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 8765

# ========= 서버 API =========
def api_login(username: str, password: str) -> str:
    r = requests.post(f"{API_BASE}/api/login", json={"username": username, "password": password}, timeout=10)
    if r.status_code != 200:
        try: msg = r.json().get("error")
        except Exception: msg = None
        raise RuntimeError(msg or f"로그인 실패 (HTTP {r.status_code})")
    return r.json()["token"]

def api_get_ascii_map(token: str):
    r = requests.get(f"{API_BASE}/api/me/ascii-map", headers={"Authorization": f"Bearer {token}"}, timeout=10)
    if r.status_code != 200:
        try: msg = r.json().get("error")
        except Exception: msg = None
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

    def push_event(self, ch: str, remapped: str, cipher_hex: str):
        if not (self.loop and self.event_q): return
        ev = {"type":"event","ts":time.time(),"input":ch,"mapped":remapped,"cipher_hex":cipher_hex[:40]}
        self.loop.call_soon_threadsafe(self.event_q.put_nowait, ev)

    def start(self, host=DASHBOARD_HOST, port=DASHBOARD_PORT):
        if self.thread: return
        self.thread = threading.Thread(target=self._run, args=(host,port), daemon=True)
        self.thread.start()
        webbrowser.open(f"http://{host}:{port}/")

    def _run(self, host, port):
        self.loop = asyncio.new_event_loop(); asyncio.set_event_loop(self.loop)
        self.event_q = asyncio.Queue()
        self.app = FastAPI(); app = self.app

        @app.get("/")
        def index():  return HTMLResponse(DASHBOARD_HTML)

        @app.get("/mapping")
        def mapping():
            try: return JSONResponse(self.mapping_getter() or {})
            except Exception: return JSONResponse({})

        @app.websocket("/ws")
        async def ws_endpoint(ws: WebSocket):
            await ws.accept(); self.clients.add(ws)
            try:
                while True: await asyncio.sleep(1.0)
            finally:
                self.clients.discard(ws)

        async def broadcaster_task():
            last_cpu_push=0.0
            while True:
                try:
                    ev = await asyncio.wait_for(self.event_q.get(), timeout=0.2)
                    dead=[]
                    for ws in list(self.clients):
                        try: await ws.send_text(json.dumps(ev))
                        except Exception: dead.append(ws)
                    for d in dead: self.clients.discard(d)
                except asyncio.TimeoutError: pass

                now=time.time()
                if now-last_cpu_push>=0.5:
                    payload={"type":"cpu","proc_cpu":self.proc.cpu_percent(interval=None),
                             "crypto_ms":float(self.crypto_ms_getter() or 0.0)}
                    dead=[]
                    for ws in list(self.clients):
                        try: await ws.send_text(json.dumps(payload))
                        except Exception: dead.append(ws)
                    for d in dead: self.clients.discard(d)
                    last_cpu_push=now

        config = uvicorn.Config(app, host=host, port=port, log_level="warning", loop="asyncio")
        self.server = uvicorn.Server(config)
        task = self.loop.create_task(broadcaster_task())
        try: self.loop.run_until_complete(self.server.serve())
        finally:
            task.cancel()
            try: self.loop.run_until_complete(task)
            except Exception: pass

    def push_close_signal(self):
        if self.loop and self.loop.is_running():
            async def _broadcast_close():
                msg=json.dumps({"type":"close"})
                await asyncio.gather(*[ws.send_text(msg) for ws in list(self.clients)], return_exceptions=True)
            fut = asyncio.run_coroutine_threadsafe(_broadcast_close(), self.loop)
            try: fut.result(timeout=1.0)
            except Exception: pass

    def stop(self):
        if self.loop and self.server:
            self.loop.call_soon_threadsafe(setattr, self.server, 'should_exit', True)
        if self.thread: self.thread.join(timeout=2.0)
        self.thread=None; self.loop=None; self.app=None; self.server=None; self.clients.clear()

# ========= 후킹 + 수집 + 실시간 검증 =========
class HookEngine:
    def __init__(self, mapping, encryptor, ui_status_cb, dashboard=None, api_base=API_BASE, api_token=None):
        self.mapping = mapping
        self.encryptor = encryptor
        self.ui_status_cb = ui_status_cb
        self.dashboard = dashboard
        self.api_base = api_base
        self.api_token = api_token

        self._listener=None; self._running=False
        self.total_time=0.0; self.last_crypto_ms=0.0

        # 수집 상태
        self.learn_active=False
        self.learn_session_id=None
        self.learn_buf=[]; self.learn_lock=threading.Lock()
        self.down_map={}     # code -> (t_down_mono, ts_down_epoch_ms)
        self.last_up_mono=None
        self.last_up_code=None

        self._flush_thread=None; self._flush_stop=threading.Event()

        # 실시간 인증 버퍼 및 주기 플러시
        self.verify_buf=[]; self.verify_lock=threading.Lock()
        self.VERIFY_BATCH_SIZE=8       # 빠른 피드백
        self.VERIFY_FLUSH_SEC=2.0      # 2초 이상 대기하면 강제 전송
        self._verify_timer=None
        self._last_verify_send = 0.0

    def _code_of(self, key):
        try: return f"Char.{key.char}"
        except AttributeError:
            try: return f"Key.{key.name}"
            except Exception: return str(key)

    def _headers(self):
        return {"Authorization": f"Bearer {self.api_token}", "Content-Type": "application/json"} if self.api_token else {"Content-Type":"application/json"}

    # ====== 서버 통신(학습) ======
    def start_learning(self, min_events=600, policy="threshold"):
        if self.learn_active: return
        if not self.api_token: raise RuntimeError("토큰 없음: 로그인 후 사용하세요.")
        r = requests.post(f"{self.api_base}/api/pattern/start", headers=self._headers(),
                          json={"min_events": int(min_events), "policy": policy}, timeout=10)
        j = r.json()
        if not r.ok or not j.get("ok"): raise RuntimeError(f"start 실패: {j}")
        self.learn_session_id = j["session_id"]; self.learn_active=True
        self._flush_stop.clear()
        self._flush_thread = threading.Thread(target=self._flush_daemon, daemon=True); self._flush_thread.start()

    def stop_learning(self):
        if not self.learn_active: return
        try:
            self._flush_once(force=True)
            requests.post(f"{self.api_base}/api/pattern/stop", headers=self._headers(),
                          json={"session_id": self.learn_session_id}, timeout=5)
        finally:
            self.learn_active=False; self.learn_session_id=None
            self._flush_stop.set()
            if self._flush_thread:
                self._flush_thread.join(timeout=2.0); self._flush_thread=None

    def _flush_daemon(self):
        while not self._flush_stop.is_set():
            self._flush_once()
            self._flush_stop.wait(1.5)

    def _flush_once(self, force=False):
        if not self.learn_active or not self.learn_session_id: return
        with self.learn_lock:
            if not self.learn_buf: return
            if not force and len(self.learn_buf) < 120: return
            batch = self.learn_buf[:]; self.learn_buf.clear()
        try:
            r = requests.post(f"{self.api_base}/api/pattern/collect", headers=self._headers(),
                              json={"session_id": self.learn_session_id, "samples": batch}, timeout=10)
            j = r.json()
            if j.get("stop"):
                self.learn_active=False; self.learn_session_id=None
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
            r = requests.post(f"{self.api_base}/api/pattern/verify",
                              headers=self._headers(), json={"samples": batch}, timeout=6)
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
            if has_buf and (time.time() - self._last_verify_send) >= self.VERIFY_FLUSH_SEC:
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
                if self.dashboard: self.dashboard.push_event(ch, remapped, ct.hex())
        except AttributeError:
            pass

        # 학습: keydown 기록
        code = self._code_of(key)
        if code not in self.down_map:
            self.down_map[code] = (time.perf_counter(), round(time.time()*1000, 3))  # mono, epoch_ms

    def _on_release(self, key):
        code = self._code_of(key)
        t_up_mono = time.perf_counter()
        if code in self.down_map:
            t_down_mono, ts_down_epoch_ms = self.down_map.pop(code)
            dwell = (t_up_mono - t_down_mono) * 1000.0  # ms
            flight = None if self.last_up_mono is None else (t_down_mono - self.last_up_mono) * 1000.0
            ts_up_epoch_ms = round(time.time()*1000, 3)
            try: kchar = key.char
            except AttributeError: kchar = ""

            # 학습 버퍼
            if self.learn_active:
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
                if len(self.learn_buf) >= 120:
                    self._flush_once(False)

            # 실시간 인증 버퍼(수집 여부와 무관)
            if flight is not None and dwell > 0:
                live = {
                    "ts_down": ts_down_epoch_ms,
                    "ts_up":   ts_up_epoch_ms,
                    "dwell_ms": round(dwell, 3),
                    "flight_ms": round(flight, 3),
                    "code": code,
                    "prev_code": (self.last_up_code or "")
                }
                with self.verify_lock:
                    self.verify_buf.append(live)
                    nbuf = len(self.verify_buf)
                # 배치 도달 시 즉시 검증
                if nbuf >= self.VERIFY_BATCH_SIZE:
                    threading.Thread(target=self._verify_typing_pattern, daemon=True).start()

            self.last_up_mono = t_up_mono
            self.last_up_code = code

    def start(self):
        if self._running: return
        self._running = True
        self._listener = keyboard.Listener(on_press=self._on_press, on_release=self._on_release)
        self._listener.start()
        # 주기 플러시 타이머 시작
        self._verify_timer = threading.Thread(target=self._verify_timer_loop, daemon=True)
        self._verify_timer.start()
        self.ui_status_cb("암호화 ON (ESC로 종료 가능)")

    def stop(self):
        if self.learn_active:
            try: self.stop_learning()
            except: pass
        if self._listener: self._listener.stop()
        self._running=False
        self.ui_status_cb("암호화 OFF")

# ========= GUI =========
class App:
    def __init__(self):
        self.root = Tk()
        self.root.title("KIM&JANG Secure Keyboard")
        self.root.geometry("360x300"); self.root.resizable(False, False)

        self.center = Frame(self.root); self.center.pack(expand=True, fill="both")
        self.form = Frame(self.center);  self.form.place(relx=0.5, rely=0.5, anchor="center")

        Label(self.form, text="로그인", font=("Malgun Gothic", 12, "bold")).grid(row=0, column=0, columnspan=2, pady=(10,4))

        self.id_var=StringVar(); self.pw_var=StringVar()
        self.msg_var=StringVar(value="회원가입 후 아이디/비밀번호로 로그인하세요.")
        self.id_entry=Entry(self.form, textvariable=self.id_var, width=34)
        self.pw_entry=Entry(self.form, textvariable=self.pw_var, width=34, show="*")
        self.id_entry.grid(row=1, column=0, columnspan=2, padx=20, pady=6)
        self.pw_entry.grid(row=2, column=0, columnspan=2, padx=20, pady=6)

        self.btn_login  = Button(self.form, text="로그인",   width=32, command=self.on_login)
        self.btn_signup = Button(self.form, text="회원가입", width=16, command=self.on_signup)
        self.btn_logout = Button(self.form, text="로그아웃", width=16, command=self.on_logout, state=DISABLED)
        self.btn_learn  = Button(self.form, text="패턴 학습 시작", width=32, state=DISABLED, command=self.on_toggle_learn)
        self.btn_analyze= Button(self.form, text="수집 데이터 분석", width=32, state=DISABLED, command=self.on_analyze)

        self.btn_login.grid(row=3, column=0, columnspan=2, padx=20, pady=(8,4))
        self.btn_signup.grid(row=4, column=0, padx=(20,6), pady=(0,8), sticky="e")
        self.btn_logout.grid(row=4, column=1, padx=(6,20),  pady=(0,8), sticky="w")
        self.btn_learn.grid(row=5, column=0, columnspan=2, padx=20, pady=(0,6))
        self.btn_analyze.grid(row=6, column=0, columnspan=2, padx=20, pady=(0,8))

        self.lbl_msg = Label(self.form, textvariable=self.msg_var, fg="#444", wraplength=380, justify="left")
        self.lbl_msg.grid(row=7, column=0, columnspan=2, padx=20, pady=(2,10))

        self.hook=None; self.dashboard=None; self._token=None; self._toggle_busy=False
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def set_status(self, text: str):
        self.root.after(0, lambda: self.msg_var.set(text))

    def on_signup(self):
        if SIGNUP_URL: webbrowser.open(SIGNUP_URL)
        self.set_status("브라우저에서 회원가입을 완료한 뒤, 이 창에서 로그인하세요.")

    def on_login(self):
        username = self.id_var.get().strip().lower()
        password = self.pw_var.get()
        if not username or not password:
            self.set_status("아이디/비밀번호를 입력하세요."); return
        self.btn_login.config(state=DISABLED); self.set_status("서버 로그인 중…")
        threading.Thread(target=self._login_flow, args=(username, password), daemon=True).start()

    def _login_flow(self, username, password):
        try:
            token = api_login(username, password); self._token = token
            self.set_status("매핑 다운로드 중…")
            mapping, version = api_get_ascii_map(token)

            user_secret=secrets.token_bytes(32); salt=secrets.token_bytes(32)
            session_key=derive_session_key(user_secret, salt)
            encryptor=AESEncryptor(session_key)

            def get_crypto_ms(): return self.hook.last_crypto_ms if self.hook else 0.0
            self.dashboard = DashboardServer(lambda: mapping, get_crypto_ms); self.dashboard.start()

            self.hook = HookEngine(mapping, encryptor, self.set_status,
                                   dashboard=self.dashboard, api_base=API_BASE, api_token=token)
            self.hook.start()

            self.set_status(f"로그인 성공! 매핑 v{version} 적용. 키 입력을 암호화합니다.")
            self.root.after(0, lambda: (self.btn_logout.config(state=NORMAL),
                                        self.btn_learn.config(state=NORMAL),
                                        self.btn_analyze.config(state=NORMAL)))
        except Exception as e:
            self.set_status(f"에러: {e}")
            self.root.after(0, lambda: self.btn_login.config(state=NORMAL))

    def on_toggle_learn(self):
        if not self.hook: self.set_status("로그인 후 사용하세요."); return
        if self._toggle_busy: return
        self._toggle_busy=True; self.btn_learn.config(state=DISABLED); self.set_status("처리 중…")
        def _run():
            try:
                if self.hook.learn_active:
                    self.hook.stop_learning()
                    self.set_status("패턴 학습 정지됨.")
                    self.root.after(0, lambda: self.btn_learn.config(text="패턴 학습 시작"))
                else:
                    self.hook.start_learning(min_events=600, policy="threshold")
                    self.set_status("패턴 학습 수집 시작… 타이핑해주세요.")
                    self.root.after(0, lambda: self.btn_learn.config(text="패턴 학습 정지"))
            except Exception as e:
                self.set_status(f"패턴 학습 오류: {e}")
            finally:
                self._toggle_busy=False
                self.root.after(0, lambda: self.btn_learn.config(state=NORMAL))
        threading.Thread(target=_run, daemon=True).start()

    # 분석 버튼
    def on_analyze(self):
        if not self._token: self.set_status("분석을 위해 먼저 로그인하세요."); return
        self.btn_analyze.config(state=DISABLED); self.set_status("서버에 데이터 분석 요청 중…")
        def _run():
            try:
                r = requests.post(f"{API_BASE}/api/pattern/analyze", headers={"Authorization": f"Bearer {self._token}"}, timeout=60)
                if r.status_code == 200:
                    msg = r.json().get("message","분석 완료")
                    self.set_status(f"성공: {msg}")
                else:
                    try: err = r.json().get("error","")
                    except Exception: err = ""
                    self.set_status(f"분석 실패: HTTP {r.status_code} {err}")
            except Exception as e:
                self.set_status(f"분석 요청 실패: {e}")
            finally:
                self.root.after(0, lambda: self.btn_analyze.config(state=NORMAL))
        threading.Thread(target=_run, daemon=True).start()

    def on_logout(self):
        try:
            if self.dashboard:
                try: self.dashboard.push_close_signal()
                except: pass
            if self.hook and self.hook.learn_active:
                try: self.hook.stop_learning()
                except: pass
            if self.hook: self.hook.stop(); self.hook=None
            if self.dashboard: self.dashboard.stop(); self.dashboard=None
        finally:
            self._token=None; self._toggle_busy=False
            self.id_var.set(""); self.pw_var.set("")
            self.btn_login.config(state=NORMAL)
            self.btn_logout.config(state=DISABLED)
            self.btn_learn.config(state=DISABLED, text="패턴 학습 시작")
            self.btn_analyze.config(state=DISABLED)
            self.set_status("로그아웃 되었습니다. 다시 로그인하세요.")

    def on_close(self):
        try:
            if self.hook and self.hook.learn_active:
                try: self.hook.stop_learning()
                except: pass
            if self.hook: self.hook.stop()
            if self.dashboard: self.dashboard.stop()
        finally:
            self.root.destroy()

    def run(self): self.root.mainloop()

if __name__ == "__main__":
    App().run()
