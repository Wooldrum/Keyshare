import asyncio, json, threading, sys, uuid, socket, platform, os
import websockets
from pynput.keyboard import Listener, Controller, Key

# ─── CONFIG ────────────────────────────────────────────────────────────────
AdvancedMode    = False        # set True to enable custom port prompt
DEFAULT_PORT    = 6969         # default port if not in advanced mode
ALLOWED         = {'w','a','s','d','e','space', *map(str, range(10))}
INSTANCE_ID     = str(uuid.uuid4())
ctrl            = Controller()
# ─────────────────────────────────────────────────────────────────────────────

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

OS          = platform.system()
clients     = set()
outbound    = set()
in_info     = {}
out_info    = {}
paused      = False
loop        = None
PORT        = DEFAULT_PORT

hs_counter      = 0
hs_futures      = {}
hs_requests     = {}

def validate_ip(addr):
    if addr.lower()=="localhost": return True
    try: socket.inet_aton(addr); return True
    except: return False

def prompt_consent():
    print(f"{Colors.GREEN}Welcome to Keyshare, developed by Wooldrum.{Colors.RESET}\nDetected OS: {OS}")
    if OS=="Darwin":  print(f"{Colors.YELLOW}  macOS: You may need to grant Accessibility perms{Colors.RESET}")
    if OS=="Linux":   print(f"{Colors.YELLOW}  Linux: You may need sudo or uinput perms{Colors.RESET}")
    if OS=="Windows": print(f"{Colors.YELLOW}  Windows: You may need to run as Admin{Colors.RESET}")
    print(f"""
{Colors.YELLOW}WARNING: Keyshare broadcasts your keyboard inputs to peers, and has an inherent malicious risk.{Colors.RESET}
• If streaming/recording, hide this window to avoid exposing your IP.
• Peers see your IP, which may expose you to possible DDoS or location leaks.
• P2P-only, no end-to-end encryption—use at your own risk.
Default port: {DEFAULT_PORT}{' (customizable in advanced mode)' if AdvancedMode else ''}
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
        val = input(f"{Colors.GREEN}{prompt}{' ['+default+']' if default else ''}: {Colors.RESET}").strip()
        if not val and default: return default
        if validate_ip(val): return val
        print(f"{Colors.RED}Invalid IP. Try again.{Colors.RESET}")

def input_peers():
    while True:
        first_user_response = input(f"{Colors.GREEN}Are you the first person in the group? (yes/no): {Colors.RESET}").strip().lower()
        if first_user_response in ("yes", "y"):
            print(f"{Colors.BLUE}Okay, you are the host. Waiting for others to connect to you...{Colors.RESET}")
            return []
        elif first_user_response in ("no", "n"):
            break
        else:
            print(f"{Colors.RED}Invalid response. Please enter 'yes' or 'no'.{Colors.RESET}")

    while True:
        raw = input(f"{Colors.GREEN}Enter the IP of at least one other person in the group (comma separated): {Colors.RESET}").strip()
        if not raw:
            print(f"\n{Colors.RED}To join, you must enter the IP address of someone already in the session.{Colors.RESET}")
            continue
        
        parts = [p.strip() for p in raw.split(",")]
        if all(validate_ip(p) for p in parts):
            return parts
        print(f"{Colors.RED}One or more IPs were invalid. Please try again.{Colors.RESET}")

def inject(key_name, typ):
    try:
        key = Key.space if key_name == "space" else key_name
        if typ == "down":
            ctrl.press(key)
        else:
            ctrl.release(key)
    except Exception as e:
        print(f"{Colors.RED}[!] Injection error: {e}{Colors.RESET}")

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
        print(f"{Colors.YELLOW}[?] ({hid}) {user}[{ip}] wants to connect. Type 'allow {hid}' or 'deny {hid}'.{Colors.RESET}")

        allow = await fut
        del hs_futures[hid], hs_requests[hid]
        if not allow:
            await ws.send(json.dumps({"type": "handshake_response", "allow": False}))
            await ws.close()
            return

        await ws.send(json.dumps({"type": "handshake_response", "allow": True}))
        
        clients.add(ws)
        in_info[ws] = (user, ip)
        print(f"{Colors.GREEN}[+] in: {user}[{ip}]{Colors.RESET}")
        
        async for raw in ws:
            d = json.loads(raw)
            if d.get("origin") == INSTANCE_ID: continue
            if not paused:
                inject(d["key"], d["type"])
            await broadcast(d, exclude={ws})

    except websockets.ConnectionClosed:
        pass
    finally:
        if ws in clients:
            user, ip = in_info.pop(ws, ("?","?"))
            print(f"{Colors.BLUE}[-] disconnected: {user}[{ip}]{Colors.RESET}")
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
                print(f"{Colors.GREEN}[+] out: {addr}{Colors.RESET}")
                asyncio.create_task(handle_peer(ws))
            else:
                print(f"{Colors.RED}[-] out denied: {addr}{Colors.RESET}")
                await ws.close()
        except Exception as e:
            print(f"{Colors.RED}[!] Connection to {addr} failed: {e}{Colors.RESET}")

async def handle_peer(ws):
    try:
        async for raw in ws:
            d = json.loads(raw)
            if d.get("origin") == INSTANCE_ID: continue
            if not paused:
                inject(d["key"], d["type"])
            await broadcast(d, exclude={ws})
    except websockets.ConnectionClosed:
        pass
    finally:
        if ws in outbound:
            addr = out_info.pop(ws, "?")
            print(f"{Colors.BLUE}[-] out disconnected: {addr}{Colors.RESET}")
            outbound.discard(ws)

async def broadcast(msg, exclude=None):
    targets = (clients | outbound) - (exclude or set())
    if targets:
        data = json.dumps(msg)
        tasks = [w.send(data) for w in targets]
        await asyncio.gather(*tasks, return_exceptions=True)

def handle_key(k, typ):
    if paused or not loop: return
    try: ch = k.char.lower()
    except: ch = "space" if k==Key.space else None
    
    if ch in ALLOWED:
        pkt = {"origin":INSTANCE_ID,"key":ch,"type":typ}
        asyncio.run_coroutine_threadsafe(broadcast(pkt), loop)

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
                print(f"{Colors.BLUE} IN:{Colors.RESET}", ins or "none"); print(f"{Colors.BLUE}OUT:{Colors.RESET}", outs or "none")
            elif cmd in ("allow","deny") and len(line)==2 and line[1].isdigit():
                hid = int(line[1])
                fut = hs_futures.get(hid)
                if fut and not fut.done():
                    fut.set_result(cmd=="allow")
                    print(f"{Colors.GREEN if cmd=='allow' else Colors.RED}Request #{hid} has been {'allowed' if cmd=='allow' else 'denied'}.{Colors.RESET}")
                else:
                    print(f"{Colors.RED}No pending request #{hid}{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}cmds:{Colors.RESET}", ", ".join(sorted(cmds)))
        except (EOFError, KeyboardInterrupt):
            if loop: loop.call_soon_threadsafe(loop.stop)
            break

async def main():
    global loop, PORT
    loop = asyncio.get_running_loop()

    prompt_consent()
    username = input(f"{Colors.GREEN}Username: {Colors.RESET}").strip() or "Anonymous"

    if AdvancedMode:
        while True:
            try:
                p = input(f"{Colors.GREEN}Set port (1024–65535) [default {DEFAULT_PORT}]: {Colors.RESET}").strip()
                PORT = int(p) if p else DEFAULT_PORT
                if 1024 <= PORT <= 65535: break
            except: pass
            print(f"{Colors.RED}Invalid port. Try again.{Colors.RESET}")
    
    print(f"{Colors.BLUE}Using port: {PORT}{Colors.RESET}")
    local_ip = input_ip("Your LAN IP (Press ENTER if this is correct)", default=get_local_ip())
    peers = input_peers()
    
    server = await websockets.serve(ws_handler, local_ip, PORT)
    print(f"{Colors.GREEN}✅ Server running on {local_ip}:{PORT}{Colors.RESET}")
    
    threading.Thread(target=start_hook, daemon=True).start()
    threading.Thread(target=cmd_loop, daemon=True).start()
    
    if peers:
        asyncio.create_task(connect(peers, local_ip, username))
    
    print(f"{Colors.GREEN}✅ Ready. Commands: pause | resume | stop | peers | allow <#> | deny <#>{Colors.RESET}")
    
    try:
        await server.wait_closed()
    finally:
        server.close()

if __name__=="__main__":
    if OS == "Windows":
        os.system('') 
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}Exiting program.{Colors.RESET}")
