# keyshare_web_gui.py

import eel
import asyncio
import json
import threading
import sys
import uuid
import socket
import platform
import os
import functools
import urllib.parse
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
import websockets
from pynput.keyboard import Listener, Controller, Key

# --- CONFIG ---
DEFAULT_PORT = 6969
OVERLAY_WS_PORT = 6970
OVERLAY_HTTP_PORT = 8000
DEFAULT_ALLOWED = {'w', 'a', 's', 'd', 'e', 'space', *map(str, range(10))}
ALL_KEYS = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
    'space', 'enter', 'shift', 'ctrl', 'alt', 'tab', 'esc'
]
INSTANCE_ID = str(uuid.uuid4())
OS = platform.system()
VIS_DIR = os.path.join(os.path.dirname(__file__), "visualizer")


# --- App State (Global) ---
app_state = {
    "clients": set(),
    "outbound": set(),
    "in_info": {},
    "out_info": {},
    "paused": False,
    "session_active": False,
    "network_loop": None,
    "server": None,
    "config_version": 1,
    "allowed_keys": DEFAULT_ALLOWED.copy(),
    "ctrl": Controller(),
    "listener_thread": None,
    "username": "Anonymous",
    "overlay_on": False,
    "overlay_clients": set()
}

# --- Eel Exposed Functions (Python -> JS) ---
def log_message(message):
    eel.logMessage(message)

def update_peer_list():
    in_peers = [f"[IN] {info[0]} ({info[1]})" for info in app_state["in_info"].values()]
    out_peers = [f"[OUT] {addr}" for addr in app_state["out_info"].values()]
    eel.updatePeerList(in_peers + out_peers)

def ask_for_permission(user, ip, future):
    try:
        allow = eel.askForPermission(user, ip)().get()
        app_state["network_loop"].call_soon_threadsafe(future.set_result, allow)
    except Exception:
        app_state["network_loop"].call_soon_threadsafe(future.set_result, False)

def confirm_new_keys(host, new_keys, future):
    try:
        keys_str = ', '.join(sorted(list(new_keys)))
        consent = eel.confirmNewKeys(host, keys_str)().get()
        app_state["network_loop"].call_soon_threadsafe(future.set_result, consent)
    except Exception:
        app_state["network_loop"].call_soon_threadsafe(future.set_result, False)

# --- Eel Exposed Functions (JS -> Python) ---
@eel.expose
def start_hosting(username, enable_overlay):
    if app_state["session_active"]: return
    app_state["username"] = username if username else "Anonymous"
    app_state["overlay_on"] = enable_overlay
    app_state["session_active"] = True
    threading.Thread(target=host_thread, daemon=True).start()
    eel.setSessionState(True, True)

@eel.expose
def join_session(username, peer_ip, enable_overlay):
    if app_state["session_active"]: return
    if not validate_ip(peer_ip):
        log_message(f"[ERROR] Invalid Peer IP: {peer_ip}")
        return

    app_state["username"] = username if username else "Anonymous"
    app_state["overlay_on"] = enable_overlay
    app_state["session_active"] = True
    app_state["peers_to_connect"] = [peer_ip]
    threading.Thread(target=join_thread, daemon=True).start()
    eel.setSessionState(True, False)

@eel.expose
def stop_session():
    if not app_state["session_active"]: return
    if app_state["network_loop"] and app_state["network_loop"].is_running():
        app_state["network_loop"].call_soon_threadsafe(app_state["stop_future"].set_result, None)
    
    app_state["clients"].clear()
    app_state["outbound"].clear()
    app_state["in_info"].clear()
    app_state["out_info"].clear()
    app_state["session_active"] = False
    log_message("Session stopped.")
    update_peer_list()
    eel.setSessionState(False, False)

@eel.expose
def toggle_pause(is_paused):
    app_state["paused"] = is_paused
    log_message(f"Session {'Paused' if is_paused else 'Resumed'}.")

@eel.expose
def save_keys(new_keys_list):
    new_keys = set(new_keys_list)
    if new_keys != app_state["allowed_keys"]:
        app_state["allowed_keys"] = new_keys
        app_state["config_version"] += 1
        log_message("Allowed keys updated. Broadcasting to peers...")
        update_msg = {"type": "config_update", "allowed_keys": list(app_state["allowed_keys"]), "config_version": app_state["config_version"]}
        asyncio.run_coroutine_threadsafe(broadcast(update_msg), app_state["network_loop"])

@eel.expose
def get_initial_keys():
    return list(app_state["allowed_keys"])

# --- Visualizer Logic ---
async def overlay_broadcast(pkt):
    if not app_state["overlay_clients"]: return
    data = json.dumps(pkt)
    dead = []
    for ws in list(app_state["overlay_clients"]):
        try: await ws.send(data)
        except: dead.append(ws)
    for ws in dead: app_state["overlay_clients"].discard(ws)

async def send_player_list_to_overlay():
    players = [app_state["username"]] + [info[0] for info in app_state["in_info"].values()]
    await overlay_broadcast({"type": "players", "players": players})

async def overlay_ws(ws):
    app_state["overlay_clients"].add(ws)
    try:
        await send_player_list_to_overlay()
        async for _ in ws: pass
    finally:
        app_state["overlay_clients"].discard(ws)

# --- THIS IS THE NEW, MORE RELIABLE SERVER ---
class DirectoryHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=VIS_DIR, **kwargs)

def start_static_server():
    if not os.path.isdir(VIS_DIR):
        log_message(f"[ERROR] Visualizer folder not found at {VIS_DIR}")
        return
    
    httpd = ThreadingHTTPServer(("0.0.0.0", OVERLAY_HTTP_PORT), DirectoryHandler)
    httpd.serve_forever()

async def start_overlay_servers():
    try:
        server = await websockets.serve(overlay_ws, "", OVERLAY_WS_PORT)
        threading.Thread(target=start_static_server, daemon=True).start()
        query = urllib.parse.urlencode({"ws": f"ws://127.0.0.1:{OVERLAY_WS_PORT}"})
        url = f"http://127.0.0.1:{OVERLAY_HTTP_PORT}/index.html?{query}"
        log_message(f"✅ Visualizer ready → {url}")
        return server
    except Exception as e:
        log_message(f"[ERROR] Visualizer failed to start: {e}")
        return None

# --- Networking Main Tasks ---
def host_thread():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    app_state["network_loop"] = loop
    loop.run_until_complete(main_host_task())
    loop.close()

async def main_host_task():
    try:
        if app_state["overlay_on"]:
            overlay_server = await start_overlay_servers()
            if not overlay_server:
                log_message("[ERROR] Could not start overlay server. Aborting.")
                return

        local_ip = get_local_ip()
        keyshare_server = await websockets.serve(ws_handler, local_ip, DEFAULT_PORT)
        app_state["server"] = keyshare_server
        log_message(f"✅ Keyshare server running on {local_ip}:{DEFAULT_PORT}")
        start_keyboard_listener()

        app_state["stop_future"] = app_state["network_loop"].create_future()
        await app_state["stop_future"]

    except Exception as e:
        log_message(f"[ERROR] during session: {e}")
    finally:
        if app_state.get("server"):
            app_state["server"].close()
            await app_state["server"].wait_closed()
        if 'overlay_server' in locals() and overlay_server:
            overlay_server.close()
            await overlay_server.wait_closed()
        log_message("Network loop closed.")

def join_thread():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    app_state["network_loop"] = loop
    loop.run_until_complete(main_join_task())
    loop.close()

async def main_join_task():
    try:
        if app_state["overlay_on"]:
            overlay_server = await start_overlay_servers()
            if not overlay_server:
                log_message("[ERROR] Could not start overlay server. Aborting.")
                return

        local_ip = get_local_ip()
        start_keyboard_listener()
        
        connect_tasks = [connect_to_peers(app_state["peers_to_connect"], local_ip, app_state["username"])]
        asyncio.gather(*connect_tasks)

        app_state["stop_future"] = app_state["network_loop"].create_future()
        await app_state["stop_future"]

    except Exception as e:
        log_message(f"[ERROR] during session: {e}")
    finally:
        if 'overlay_server' in locals() and overlay_server:
            overlay_server.close()
            await overlay_server.wait_closed()
        log_message("Network loop closed.")

# --- Networking Handlers ---
async def ws_handler(ws, path):
    try:
        req = json.loads(await ws.recv())
        if req.get("type") != "handshake_request": return await ws.close()
        user, ip = req["username"], req["ip"]

        fut = app_state["network_loop"].create_future()
        eel.spawn(ask_for_permission, user, ip, fut)
        allow = await fut

        if not allow:
            await ws.send(json.dumps({"type": "handshake_response", "allow": False}))
            return await ws.close()

        await ws.send(json.dumps({"type": "handshake_response", "allow": True, "allowed_keys": list(app_state["allowed_keys"]), "config_version": app_state["config_version"]}))
        
        app_state["clients"].add(ws)
        app_state["in_info"][ws] = (user, ip)
        log_message(f"[+] in: {user}[{ip}]")
        update_peer_list()
        if app_state["overlay_on"]: await send_player_list_to_overlay()

        async for raw in ws:
            d = json.loads(raw)
            if d.get("origin") == INSTANCE_ID: continue
            d.setdefault("user", user)
            if not app_state["paused"]: inject_key(d["key"], d["type"])
            await broadcast(d, exclude={ws})

    except websockets.ConnectionClosed: pass
    finally:
        if ws in app_state["clients"]:
            u, ip = app_state["in_info"].pop(ws, ("?", "?"))
            app_state["clients"].discard(ws)
            log_message(f"[-] disconnected: {u}[{ip}]")
            update_peer_list()
            if app_state["overlay_on"]: await send_player_list_to_overlay()

async def connect_to_peers(peers, local_ip, uname):
    for addr in peers:
        uri = f"ws://{addr}:{DEFAULT_PORT}"
        try:
            ws = await websockets.connect(uri)
            await ws.send(json.dumps({"type": "handshake_request", "username": uname, "ip": local_ip}))
            res = json.loads(await ws.recv())

            is_allowed = res.get("type") == "handshake_response" and res.get("allow")
            if not is_allowed:
                log_message(f"[ERROR] Connection to {addr} denied.")
                await ws.close()
                continue

            new_allowed = set(res.get('allowed_keys', DEFAULT_ALLOWED))
            consent_given = True
            
            if new_allowed != app_state["allowed_keys"]:
                fut = app_state["network_loop"].create_future()
                eel.spawn(confirm_new_keys, addr, new_allowed, fut)
                consent_given = await fut
            
            if not consent_given:
                log_message(f"Connection to {addr} cancelled.")
                await ws.close()
                continue

            app_state["outbound"].add(ws)
            app_state["out_info"][ws] = addr
            app_state["allowed_keys"] = new_allowed
            app_state["config_version"] = res.get('config_version', 1)
            log_message(f"[+] out: {addr}")
            update_peer_list()
            if app_state["overlay_on"]: await send_player_list_to_overlay()
            
            asyncio.create_task(handle_peer(ws, addr))
        except Exception as e:
            log_message(f"[ERROR] Connection to {addr} failed: {e}")

async def handle_peer(ws, addr):
    try:
        async for raw in ws:
            d = json.loads(raw)
            if d.get("type") == "config_update":
                new_version = d.get("config_version")
                if new_version > app_state["config_version"]:
                    eel.setPauseState(True)
                    
                    fut = app_state["network_loop"].create_future()
                    new_keys = set(d.get("allowed_keys"))
                    eel.spawn(confirm_new_keys, addr, new_keys, fut)
                    consent_given = await fut
                    
                    if consent_given:
                        app_state["allowed_keys"] = new_keys
                        app_state["config_version"] = new_version
                        eel.setPauseState(False)
                        log_message("Settings updated.")
                    else:
                        log_message("Disconnecting due to settings rejection.")
                        await ws.close()
                        break
                continue

            if d.get("origin") == INSTANCE_ID: continue
            
            d.setdefault("user", addr)
            if not app_state["paused"]: inject_key(d["key"], d["type"])
            await broadcast(d, exclude={ws})
            
    except websockets.ConnectionClosed: pass
    finally:
        if ws in app_state["outbound"]:
            app_state["outbound"].discard(ws)
            app_state["out_info"].pop(ws, None)
            log_message(f"[-] out disconnected: {addr}")
            update_peer_list()
            if app_state["overlay_on"]: await send_player_list_to_overlay()

async def broadcast(msg, exclude=None):
    if app_state["overlay_on"]:
        asyncio.create_task(overlay_broadcast(msg))
    targets = (app_state["clients"] | app_state["outbound"]) - (exclude or set())
    if targets:
        data = json.dumps(msg)
        await asyncio.gather(*(w.send(data) for w in targets), return_exceptions=True)

# --- Keyboard Handling ---
def start_keyboard_listener():
    if app_state["listener_thread"] and app_state["listener_thread"].is_alive():
        return
    app_state["listener_thread"] = threading.Thread(target=_keyboard_listener_thread, daemon=True)
    app_state["listener_thread"].start()
    log_message("Keyboard listener started.")

def _keyboard_listener_thread():
    with Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

def on_press(k): handle_key(k, "down")
def on_release(k): handle_key(k, "up")

def handle_key(k, typ):
    if app_state["paused"] or not app_state["network_loop"]: return
    key_name = get_key_name(k)
    if key_name in app_state["allowed_keys"]:
        packet = {"origin": INSTANCE_ID, "user": app_state["username"], "key": key_name, "type": typ}
        asyncio.run_coroutine_threadsafe(broadcast(packet), app_state["network_loop"])

def inject_key(key_name, typ):
    try:
        key_to_press = getattr(Key, key_name) if hasattr(Key, key_name) else key_name
        if typ == "down":
            app_state["ctrl"].press(key_to_press)
        else:
            app_state["ctrl"].release(key_to_press)
    except Exception as e:
        log_message(f"[!] Injection error: {e}")

# --- Utilities ---
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.connect(("8.8.8.8", 80)); return s.getsockname()[0]
    except: return "127.0.0.1"
    finally: s.close()

def validate_ip(addr):
    if addr.lower() == "localhost": return True
    try: socket.inet_aton(addr); return True
    except socket.error: return False
            
def get_key_name(k):
    if isinstance(k, str): return k
    if isinstance(k, Key): return k.name
    if getattr(k, 'char', None): return k.char.lower()
    return None

def on_app_close(route, websockets):
    stop_session()
    sys.exit()

if __name__ == "__main__":
    eel.init('web')
    
    if OS == "Windows":
        log_message("On Windows, run as an administrator for full functionality.")
    elif OS == "Darwin":
        log_message("On macOS, grant Accessibility permissions for Keyshare.")
    elif OS == "Linux":
        log_message("On Linux, run with sudo or have uinput permissions.")
        
    eel.start('main.html', size=(960, 1080), close_callback=on_app_close)