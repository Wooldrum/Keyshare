import asyncio, json, threading, sys, uuid, socket, platform
import websockets
from pynput.keyboard import Listener, Controller, Key

# ─── CONFIG ────────────────────────────────────────────────────────────────
AdvancedMode    = False        # set True to enable custom port prompt
DEFAULT_PORT    = 6969         # default port if not in advanced mode
PORT            = DEFAULT_PORT
ALLOWED         = {'w','a','s','d','e','space', *map(str, range(10))}
INSTANCE_ID     = str(uuid.uuid4())
ctrl            = Controller()
# ─────────────────────────────────────────────────────────────────────────────

OS          = platform.system()
clients     = set()      # incoming ws
outbound    = set()      # outgoing ws
in_info     = {}         # ws -> (user, ip)
out_info    = {}         # ws -> ip
paused      = False
loop        = None       # Global loop object

# handshake queues
hs_counter      = 0
hs_futures      = {}  # id -> Future
hs_requests     = {}  # id -> (ws, user, ip)

def validate_ip(addr):
    if addr.lower()=="localhost": return True
    try: socket.inet_aton(addr); return True
    except: return False

def prompt_consent():
    print("Welcome to Keyshare, developed by Wooldrum.\nDetected OS:", OS)
    if OS=="Darwin":  print(" macOS: grant Accessibility perms")
    if OS=="Linux":   print(" Linux: may need sudo or uinput perms")
    if OS=="Windows": print(" Windows: run as Admin")
    print(f"""
WARNING: Keyshare broadcasts your keys to peers (malicious risk)
• If streaming/recording, hide this window to avoid exposing your IP.
• Peers see your IP ⇒ possible DDoS or location leaks.
• P2P-only, no end-to-end encryption—use at your own risk.
Default port: {DEFAULT_PORT}{' (customizable in advanced mode)' if AdvancedMode else ''}
""")
    if input("Do you consent? (yes/no): ").strip().lower() not in ("yes","y"):
        print("Consent denied. Exiting."); sys.exit(0)

def get_local_ip():
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    try: s.connect(("8.8.8.8",80)); return s.getsockname()[0]
    except: return "127.0.0.1"
    finally: s.close()

def input_ip(prompt, default=None):
    while True:
        val = input(f"{prompt}{' ['+default+']' if default else ''}: ").strip()
        if not val and default: return default
        if validate_ip(val): return val
        print("Invalid IP. Try again.")

def input_peers():
    while True:
        first_user_response = input("Are you the first person in the group? (yes/no): ").strip().lower()
        if first_user_response in ("yes", "y"):
            print("Okay, you are the host. Waiting for others to connect to you...")
            return []
        elif first_user_response in ("no", "n"):
            break
        else:
            print("Invalid response. Please enter 'yes' or 'no'.")

    while True:
        raw = input("Enter the IP of at least one other person in the group (comma separated): ").strip()
        if not raw:
            print("\nTo join, you must enter the IP address of someone already in the session.")
            continue
        
        parts = [p.strip() for p in raw.split(",")]
        if all(validate_ip(p) for p in parts):
            return parts
        print("One or more IPs were invalid. Please try again.")

def send_to_stringlab(e): pass  # stub

def inject(key_name, typ):
    try:
        key = Key.space if key_name == "space" else key_name
        if typ == "down":
            ctrl.press(key)
        else:
            ctrl.release(key)
    except Exception as e:
        print(f"[!] Injection error: {e}")

async def ws_handler(ws, path):
    global hs_counter
    try:
        msg = await ws.recv()
        req = json.loads(msg)
        if req.get("type") != "handshake_request":
            return await ws.close()
        user, ip = req["username"], req["ip"]

        hs_counter += 1
        hid = hs_counter
        fut = loop.create_future()
        hs_futures[hid] = fut
        hs_requests[hid] = (ws, user, ip)
        print(f"[?] ({hid}) {user}[{ip}] wants to connect. Type 'allow {hid}' or 'deny {hid}'.")

        allow = await fut
        del hs_futures[hid], hs_requests[hid]
        if not allow:
            await ws.send(json.dumps({"type": "handshake_response", "allow": False}))
            await ws.close()
            return

        await ws.send(json.dumps({"type": "handshake_response", "allow": True}))
        
        clients.add(ws)
        in_info[ws] = (user, ip)
        print(f"[+] in: {user}[{ip}]")
        
        async for raw in ws:
            d = json.loads(raw)
            if d.get("origin") == INSTANCE_ID: continue
            if not paused:
                inject(d["key"], d["type"])
                send_to_stringlab(d)
            await broadcast(d, exclude={ws})

    except websockets.ConnectionClosed:
        pass
    finally:
        if ws in clients:
            user, ip = in_info.pop(ws, ("?","?"))
            print(f"[-] disconnected: {user}[{ip}]")
            clients.discard(ws)

async def connect(peers, local_ip, uname):
    for addr in peers:
        uri = f"ws://{addr}:{PORT}"
        try:
            ws = await websockets.connect(uri)
            await ws.send(json.dumps({"type":"handshake_request","username":uname,"ip":local_ip}))
            res_raw = await ws.recv()
            res = json.loads(res_raw)
            
            if res.get("type") == "handshake_response" and res.get("allow"):
                outbound.add(ws); out_info[ws] = addr
                print(f"[+] out: {addr}")
                asyncio.create_task(handle_peer(ws))
            else:
                print(f"[-] out denied: {addr}")
                await ws.close()
        except Exception as e:
            print(f"[!] Connection to {addr} failed: {e}")

async def handle_peer(ws):
    try:
        async for raw in ws:
            d = json.loads(raw)
            if d.get("origin") == INSTANCE_ID: continue
            if not paused:
                inject(d["key"], d["type"])
                send_to_stringlab(d)
            await broadcast(d, exclude={ws})
    except websockets.ConnectionClosed:
        pass
    finally:
        if ws in outbound:
            addr = out_info.pop(ws, "?")
            print(f"[-] out disconnected: {addr}")
            outbound.discard(ws)

async def broadcast(msg, exclude=None):
    targets = (clients | outbound) - (exclude or set())
    if targets:
        data = json.dumps(msg)
        tasks = [w.send(data) for w in targets]
        await asyncio.gather(*tasks, return_exceptions=True)

def handle_key(k, typ):
    global loop
    if paused or not loop: return
    try: ch = k.char.lower()
    except: ch = "space" if k==Key.space else None
    
    if ch in ALLOWED:
        pkt = {"origin":INSTANCE_ID,"key":ch,"type":typ}
        asyncio.run_coroutine_threadsafe(broadcast(pkt), loop)
        send_to_stringlab(pkt)

def on_press(k):  handle_key(k, "down")
def on_release(k): handle_key(k, "up")

def start_hook():
    with Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

def cmd_loop():
    global paused, loop
    cmds = {"pause","resume","stop","peers","allow","deny"}
    while True:
        try:
            line = input().strip().split()
            if not line: continue
            cmd = line[0].lower()
            if cmd == "pause":
                paused=True; print("== paused ==")
            elif cmd == "resume":
                paused=False; print("== resumed ==")
            elif cmd in ("stop","exit","quit"):
                print("== stopping ==")
                if loop:
                    for ws in list(clients | outbound):
                        loop.create_task(ws.close())
                    loop.call_soon_threadsafe(loop.stop)
                break
            elif cmd == "peers":
                ins = [f"{in_info[w][0]}[{in_info[w][1]}]" for w in clients]
                outs = [out_info[w] for w in outbound]
                print(" IN:", ins or "none"); print("OUT:", outs or "none")
            elif cmd in ("allow","deny") and len(line)==2 and line[1].isdigit():
                hid = int(line[1])
                fut = hs_futures.get(hid)
                if fut and not fut.done():
                    fut.set_result(cmd=="allow")
                    print(f"Request #{hid} has been {'allowed' if cmd=='allow' else 'denied'}.")
                else:
                    print(f"No pending request #{hid}")
            else:
                print("cmds:", ", ".join(sorted(cmds)))
        except (EOFError, KeyboardInterrupt):
            if loop:
                loop.call_soon_threadsafe(loop.stop)
            break

async def main():
    global loop
    loop = asyncio.get_running_loop()

    prompt_consent()
    username = input("Username: ").strip() or "Anonymous"

    if AdvancedMode:
        while True:
            try:
                p = input(f"Set port (1024–65535) [default {DEFAULT_PORT}]: ").strip()
                PORT = int(p) if p else DEFAULT_PORT
                if 1024 <= PORT <= 65535: break
            except: pass
            print("Invalid port. Try again.")
    print(f"Using port: {PORT}")
    
    local_ip = input_ip("LAN IP", default=get_local_ip())
    peers = input_peers()
    
    # Start the server to listen for incoming connections
    server = await websockets.serve(ws_handler, local_ip, PORT)
    print(f"✅ Server running on {local_ip}:{PORT}")
    
    threading.Thread(target=start_hook, daemon=True).start()
    threading.Thread(target=cmd_loop, daemon=True).start()
    
    if peers:
        asyncio.create_task(connect(peers, local_ip, username))
    
    print("✅ Ready. Commands: pause | resume | stop | peers | allow <#> | deny <#>")
    
    await server.wait_closed()

if __name__=="__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting program.")
