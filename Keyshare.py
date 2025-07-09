import asyncio, json, threading, sys, uuid, socket, platform, os, functools, urllib.parse
import websockets
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pynput.keyboard import Listener, Controller, Key

# ─── CONFIG ────────────────────────────────────────────────────────────────
AdvancedMode      = False
DEFAULT_PORT      = 6969
OVERLAY_WS_PORT   = 6970
OVERLAY_HTTP_PORT = 8000
DEFAULT_ALLOWED   = {'w','a','s','d','e','space', *map(str, range(10))}
ALLOWED           = DEFAULT_ALLOWED.copy()
INSTANCE_ID       = str(uuid.uuid4())
VIS_DIR           = os.path.join(os.path.dirname(__file__), "visualizer")
ctrl              = Controller()
# ─────────────────────────────────────────────────────────────────────────────

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

OS              = platform.system()
clients         = set()
outbound        = set()
in_info         = {}
out_info        = {}
paused          = False
loop            = None
PORT            = DEFAULT_PORT
config_version  = 1

hs_counter      = 0
hs_futures      = {}
hs_requests     = {}

overlay_on      = False
overlay_clients = set()

def validate_ip(addr):
    if addr.lower() == "localhost": return True
    try: socket.inet_aton(addr); return True
    except: return False

def prompt_consent():
    print(f"{Colors.GREEN}Welcome to Keyshare, developed by Wooldrum.{Colors.RESET}\nDetected OS: {OS}")
    if OS=="Darwin":  print(f"{Colors.YELLOW}  macOS: On Mac, you may need to grant Accessibility permissions.{Colors.RESET}")
    if OS=="Linux":   print(f"{Colors.YELLOW}  Linux: On Linux, you may need to run with sudo or uinput permissions.{Colors.RESET}")
    if OS=="Windows": print(f"{Colors.YELLOW}  Windows: On Windows, you may need to run as an administrator.{Colors.RESET}")
    print(f"""
{Colors.YELLOW}WARNING: Keyshare broadcasts your keyboard inputs to peers, and has an inherent malicious risk.{Colors.RESET}
• If streaming/recording, hide this window to avoid exposing your IP.
• Peers see your IP, which may expose you to possible DDoS or location leaks.
• P2P-only, no end-to-end encryption — use at your own risk.
Default port: {DEFAULT_PORT}
""")
    if input(f"{Colors.GREEN}Do you consent? (yes/no): {Colors.RESET}").strip().lower() not in ("yes","y"):
        print(f"{Colors.RED}Consent denied. Exiting.{Colors.RESET}"); sys.exit(0)

def get_local_ip():
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    try: s.connect(("8.8.8.8",80)); return s.getsockname()[0]
    except: return "127.0.0.1"
    finally: s.close()

def input_ip(prompt, default=None):
    while True:
        val=input(f"{Colors.GREEN}{prompt}{' ['+default+']' if default else ''}: {Colors.RESET}").strip()
        if not val and default: return default
        if validate_ip(val):    return val
        print(f"{Colors.RED}Invalid IP. Try again.{Colors.RESET}")

def input_peers():
    while True:
        first=input(f"{Colors.GREEN}Are you the first person in the group? (yes/no): {Colors.RESET}").strip().lower()
        if first in ("yes","y"):
            print(f"{Colors.BLUE}Okay, you are the host. Waiting for others to connect to you...{Colors.RESET}")
            return []
        if first in ("no","n"): break
        print(f"{Colors.RED}Invalid response. Please enter 'yes' or 'no'.{Colors.RESET}")
    while True:
        raw=input(f"{Colors.GREEN}Enter the IP of at least one other person in the group (comma separated): {Colors.RESET}").strip()
        if not raw:
            print(f"\n{Colors.RED}To join, you must enter the IP address of someone already in the session.{Colors.RESET}")
            continue
        parts=[p.strip() for p in raw.split(",")]
        if all(validate_ip(p) for p in parts): return parts
        print(f"{Colors.RED}One or more IPs were invalid. Please try again.{Colors.RESET}")

def get_key_name(k):
    if isinstance(k,str): return k
    if isinstance(k,Key): return k.name
    if getattr(k,'char',None): return k.char.lower()
    return None

async def overlay_broadcast(pkt):
    if not overlay_clients: return
    data=json.dumps(pkt)
    dead=[]
    for ws in list(overlay_clients):
        try: await ws.send(data)
        except: dead.append(ws)
    for ws in dead: overlay_clients.discard(ws)

async def send_player_list():
    players=[USERNAME]+[in_info[w][0] for w in clients]
    await overlay_broadcast({"type":"players","players":players})

async def overlay_ws(ws):
    overlay_clients.add(ws)
    try:
        await send_player_list()
        async for _ in ws: pass
    finally:
        overlay_clients.discard(ws)

async def overlay_process_request(path,h):
    hdr=getattr(h,"headers",h)
    if hdr.get("Upgrade","").lower()=="websocket": return
    return 200,[("Content-Type","text/plain")],b"Keyshare overlay"

def start_static_server():
    if not os.path.isdir(VIS_DIR):
        print(f"{Colors.RED}[overlay] visualizer folder not found at {VIS_DIR}{Colors.RESET}")
        return
    handler=functools.partial(SimpleHTTPRequestHandler,directory=VIS_DIR)
    ThreadingHTTPServer(("0.0.0.0",OVERLAY_HTTP_PORT),handler).serve_forever()

async def start_overlay_servers():
    try:
        await websockets.serve(overlay_ws,"",OVERLAY_WS_PORT,process_request=overlay_process_request)
        threading.Thread(target=start_static_server,daemon=True).start()
    except Exception as e:
        print(f"{Colors.RED}[overlay] failed: {e}{Colors.RESET}")

async def broadcast(msg, exclude=None):
    targets=(clients|outbound) - (exclude or set())
    if targets:
        data=json.dumps(msg)
        await asyncio.gather(*(w.send(data) for w in targets), return_exceptions=True)
    if overlay_on: await overlay_broadcast(msg)

def inject(key_name, typ):
    try:
        key_to_press = getattr(Key, key_name) if hasattr(Key, key_name) else key_name
        if typ == "down":
            ctrl.press(key_to_press)
        else:
            ctrl.release(key_to_press)
    except Exception as e:
        print(f"{Colors.RED}[!] Injection error: {e}{Colors.RESET}")

async def ws_handler(ws, path):
    global hs_counter
    try:
        req=json.loads(await ws.recv())
        if req.get("type")!="handshake_request": return await ws.close()
        user, ip = req["username"], req["ip"]

        hs_counter += 1
        hid = hs_counter
        fut = loop.create_future()
        hs_futures[hid] = fut
        hs_requests[hid] = (ws,user,ip)
        print(f"\n{Colors.YELLOW}[!] Connection Request ({hid}): {user} at {ip} would like to join.\n    To accept, type 'allow {hid}'. To reject, type 'deny {hid}'.{Colors.RESET}")

        allow = await fut
        del hs_futures[hid], hs_requests[hid]
        
        if not allow:
            await ws.send(json.dumps({"type":"handshake_response","allow":False}))
            return await ws.close()

        await ws.send(json.dumps({"type":"handshake_response","allow":True,"allowed_keys":list(ALLOWED),"config_version":config_version}))
        clients.add(ws)
        in_info[ws] = (user,ip)
        print(f"{Colors.GREEN}[+] in: {user}[{ip}]{Colors.RESET}")
        
        if overlay_on: asyncio.create_task(send_player_list())

        async for raw in ws:
            d=json.loads(raw)
            if d.get("origin")==INSTANCE_ID: continue
            d.setdefault("user",user)
            if not paused: inject(d["key"],d["type"])
            await broadcast(d, exclude={ws})

    except websockets.ConnectionClosed: pass
    finally:
        if ws in clients:
            u,ip=in_info.pop(ws,("?","?"))
            clients.discard(ws)
            print(f"{Colors.BLUE}[-] disconnected: {u}[{ip}]{Colors.RESET}")
            if overlay_on: asyncio.create_task(send_player_list())

async def connect(peers, local_ip, uname):
    global ALLOWED, config_version
    for addr in peers:
        uri=f"ws://{addr}:{PORT}"
        try:
            ws=await websockets.connect(uri)
            await ws.send(json.dumps({"type":"handshake_request","username":uname,"ip":local_ip}))
            res=json.loads(await ws.recv())
            
            is_allowed = res.get("type")=="handshake_response" and res.get("allow")
            if not is_allowed:
                print(f"{Colors.RED}[-] out denied: {addr}{Colors.RESET}")
                await ws.close()
                continue

            new_allowed = set(res.get('allowed_keys', DEFAULT_ALLOWED))
            consent_given = True
            
            if new_allowed != ALLOWED:
                print(f"\n{Colors.YELLOW}WARNING: The host ({addr}) is using custom key settings.{Colors.RESET}")
                print(f"{Colors.YELLOW}The following keys will be shared: {', '.join(sorted(new_allowed))}{Colors.RESET}")
                confirm = input(f"{Colors.GREEN}Proceed with these settings? (yes/no): {Colors.RESET}").strip().lower()
                consent_given = confirm in ("yes","y")
            
            if not consent_given:
                print(f"{Colors.RED}Connection to {addr} cancelled.{Colors.RESET}")
                await ws.close()
                continue

            outbound.add(ws)
            out_info[ws] = addr
            ALLOWED = new_allowed
            config_version = res.get('config_version', 1)
            print(f"{Colors.GREEN}[+] out: {addr}{Colors.RESET}")
            
            if overlay_on: asyncio.create_task(send_player_list())

            asyncio.create_task(handle_peer(ws, addr))
        except Exception as e:
            print(f"{Colors.RED}[!] Connection to {addr} failed: {e}{Colors.RESET}")

async def handle_peer(ws, addr):
    global ALLOWED, paused, config_version
    try:
        async for raw in ws:
            d = json.loads(raw)

            if d.get("type") == "config_update":
                new_version = d.get("config_version")
                if new_version > config_version:
                    was_paused = paused
                    paused = True
                    print(f"\n{Colors.YELLOW}WARNING: The host ({addr}) has changed the key settings.{Colors.RESET}")
                    new_keys = set(d.get("allowed_keys"))
                    print(f"{Colors.YELLOW}The new keys are: {', '.join(sorted(list(new_keys)))}{Colors.RESET}")
                    
                    consent_given = False
                    while True:
                        confirm = input(f"{Colors.GREEN}Accept new settings? (yes/no): {Colors.RESET}").strip().lower()
                        if confirm in ('yes', 'y'):
                            consent_given = True
                            break
                        elif confirm in ('no', 'n'):
                            break
                    
                    if consent_given:
                        ALLOWED = new_keys
                        config_version = new_version
                        paused = was_paused
                        print(f"{Colors.BLUE}Settings updated.{Colors.RESET}")
                    else:
                        print(f"{Colors.RED}Disconnecting due to settings rejection.{Colors.RESET}")
                        await ws.close()
                        break
                continue

            if d.get("origin") == INSTANCE_ID: continue
            
            d.setdefault("user",addr)
            if not paused: inject(d["key"], d["type"])
            await broadcast(d, exclude={ws})
            
    except websockets.ConnectionClosed: pass
    finally:
        if ws in outbound:
            outbound.discard(ws)
            out_info.pop(ws,None)
            print(f"{Colors.BLUE}[-] out disconnected: {addr}{Colors.RESET}")
            if overlay_on: asyncio.create_task(send_player_list())

def on_press(k): handle_key(k, "down")
def on_release(k): handle_key(k, "up")

def handle_key(k,typ):
    if paused or not loop: return
    key=get_key_name(k)
    if key in ALLOWED:
        packet = {"origin":INSTANCE_ID,"user":USERNAME,"key":key,"type":typ}
        asyncio.run_coroutine_threadsafe(broadcast(packet), loop)

def start_hook():
    with Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

def input_allowed_keys():
    print(f"{Colors.BLUE}Current allowed keys: {', '.join(sorted(ALLOWED))}{Colors.RESET}")
    while True:
        raw=input(f"{Colors.GREEN}Enter new keys (comma separated), or press ENTER to keep current: {Colors.RESET}").strip()
        if not raw: return ALLOWED
        parts={p.strip().lower() for p in raw.split(",")}
        if all(parts):
            print(f"{Colors.BLUE}New allowed keys set.{Colors.RESET}")
            return parts
        print(f"{Colors.RED}Invalid input. Please provide a comma-separated list of keys.{Colors.RESET}")

def cmd_loop():
    global paused, ALLOWED, config_version
    base_cmds={"pause","resume","stop","peers","allow","deny"}
    
    while True:
        try:
            current_cmds = base_cmds.copy()
            if AdvancedMode:
                current_cmds.add("edit")

            line = input().strip().split()
            if not line: continue
            cmd = line[0].lower()

            if cmd == "pause":
                print(f"{Colors.YELLOW}== paused =={Colors.RESET}")
                paused=True
            elif cmd == "resume":
                print(f"{Colors.YELLOW}== resumed =={Colors.RESET}")
                paused=False
            elif cmd in ("stop","exit","quit"):
                print(f"{Colors.RED}== stopping =={Colors.RESET}")
                if loop: loop.call_soon_threadsafe(loop.stop)
                break
            elif cmd == "peers":
                ins = [f"{in_info[w][0]}[{in_info[w][1]}]" for w in clients]
                outs = [out_info[w] for w in outbound]
                print(f"{Colors.BLUE}IN:{Colors.RESET} {ins or 'none'}\n{Colors.BLUE}OUT:{Colors.RESET} {outs or 'none'}")
            elif cmd in ("allow","deny") and len(line)==2 and line[1].isdigit():
                hid=int(line[1])
                fut=hs_futures.get(hid)
                if fut and not fut.done():
                    fut.set_result(cmd=="allow")
                    print(f"{Colors.GREEN if cmd=='allow' else Colors.RED}Request #{hid} has been {'allowed' if cmd=='allow' else 'denied'}.{Colors.RESET}")
                else:
                    print(f"{Colors.RED}No pending request #{hid}{Colors.RESET}")
            elif AdvancedMode and cmd == "edit":
                print(f"{Colors.YELLOW}== Pausing for edit =={Colors.RESET}")
                paused=True
                new_keys = input_allowed_keys()
                if new_keys != ALLOWED:
                    ALLOWED = new_keys
                    config_version += 1
                    print(f"{Colors.BLUE}Broadcasting updated settings to peers...{Colors.RESET}")
                    update_msg = {"type": "config_update", "allowed_keys": list(ALLOWED), "config_version": config_version}
                    asyncio.run_coroutine_threadsafe(broadcast(update_msg), loop)
                print(f"{Colors.YELLOW}== Resuming =={Colors.RESET}")
                paused=False
            else:
                print(f"{Colors.YELLOW}cmds:{Colors.RESET} {', '.join(sorted(current_cmds))}")
        except (EOFError,KeyboardInterrupt):
            if loop: loop.call_soon_threadsafe(loop.stop)
            break

def konami_listener(activated, start_done):
    KONAMI_CODE=[Key.up,Key.up,Key.down,Key.down,Key.left,Key.right,Key.left,Key.right,'b','a']
    code_keys=[get_key_name(k) for k in KONAMI_CODE]
    recent_keys=[]
    
    def on_press(key):
        nonlocal recent_keys
        if start_done.is_set() or activated.is_set(): return False
        
        key_name = get_key_name(key)
        if key_name is None: return

        recent_keys.append(key_name)
        if len(recent_keys) > len(code_keys):
            recent_keys.pop(0)

        if recent_keys == code_keys:
            global AdvancedMode
            AdvancedMode=True
            print(f"\n{Colors.YELLOW}** ADVANCED MODE ACTIVATED **{Colors.RESET}")
            activated.set()
            return False
            
    with Listener(on_press=on_press) as l:
        l.join()

async def main():
    global loop, PORT, ALLOWED, USERNAME, overlay_on
    
    konami_activated = threading.Event()
    startup_finished = threading.Event()
    
    threading.Thread(target=konami_listener,args=(konami_activated, startup_finished),daemon=True).start()
    
    def consent_input_wrapper():
        prompt_consent()
        startup_finished.set()

    threading.Thread(target=consent_input_wrapper, daemon=True).start()

    while not startup_finished.is_set() and not konami_activated.is_set():
        await asyncio.sleep(0.1)

    loop = asyncio.get_running_loop()
    USERNAME = input(f"{Colors.GREEN}Username: {Colors.RESET}").strip() or "Anonymous"

    if AdvancedMode:
        while True:
            try:
                p=input(f"{Colors.GREEN}Set port (1024–65535) [default {DEFAULT_PORT}]: {Colors.RESET}").strip()
                PORT=int(p) if p else DEFAULT_PORT
                if 1024<=PORT<=65535: break
            except: pass
            print(f"{Colors.RED}Invalid port. Try again.{Colors.RESET}")
        ALLOWED=input_allowed_keys()

    overlay_on=input(f"{Colors.GREEN}Enable stream visualizer overlay? (yes/no): {Colors.RESET}").lower() in ("yes","y")

    overlay_layout="vertical"
    if overlay_on:
        if AdvancedMode:  
            ans=input(f"{Colors.GREEN}Stack keyboards vertically? (yes = vertical, no = horizontal): {Colors.RESET}").strip().lower()
            overlay_layout = "vertical" if ans in ("", "yes", "y") else "horizontal"
        asyncio.create_task(start_overlay_servers())

    print(f"{Colors.BLUE}Using port: {PORT}{Colors.RESET}")
    local_ip=input_ip("Your LAN IP (Press ENTER if this is correct)", default=get_local_ip())
    peers=input_peers()

    if overlay_on:
        query=urllib.parse.urlencode({"ws":f"ws://127.0.0.1:{OVERLAY_WS_PORT}","layout":overlay_layout})
        url   = f"http://127.0.0.1:{OVERLAY_HTTP_PORT}/index.html?{query}"
        print(f"{Colors.GREEN}Visualizer ready → {url}{Colors.RESET}")

    server=await websockets.serve(ws_handler, local_ip, PORT)
    print(f"{Colors.GREEN}✅ Server running on {local_ip}:{PORT}{Colors.RESET}")

    threading.Thread(target=start_hook, daemon=True).start()
    threading.Thread(target=cmd_loop, daemon=True).start()
    
    if peers: asyncio.create_task(connect(peers, local_ip, USERNAME))

    ready_cmds=["pause","resume","stop","peers","allow","deny"]
    if AdvancedMode:
        ready_cmds.append("edit")
    print(f"{Colors.GREEN}✅ Ready. Commands: {', '.join(ready_cmds)}{Colors.RESET}")
    
    try:
        await server.wait_closed()
    finally:
        server.close()

if __name__=="__main__":
    if OS=="Windows": os.system("")
    try: asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}Exiting program.{Colors.RESET}")
