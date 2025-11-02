#!/usr/bin/env python3

"""
Keyshare with P2P add‑on
========================

This script retains the original Keyshare functionality for sharing keyboard
events across a group of peers using a simple WebSocket server and client.
It also introduces an optional peer‑to‑peer (P2P) mode that allows you to
share either keyboard or mouse input directly with a single remote peer
without needing to expose ports or set up a relay. The P2P mode uses UDP
hole punching to establish a direct connection between the two peers. Once
connected, you can choose to send your keyboard events (every key press
and release) or your mouse events (movement, clicks and scrolls) to the
other machine, and any received events are replayed locally. The P2P mode
is started at runtime via the ``p2p`` command in the command prompt.

Key features:

* **WebSocket group sharing** – the classic Keyshare behaviour where one
  host accepts inbound connections and broadcasts allowed key presses to all
  connected peers. Peers may join by specifying the host IP and port.
* **Configurable keys** – hosts may restrict which keys are shared and
  propagate those settings to all participants. Participants are warned
  before accepting new key settings.
* **Interactive command interface** – type commands such as ``pause``,
  ``resume``, ``stop``, ``peers``, ``allow``/``deny`` and now ``p2p`` to
  control the application. An Easter‑egg Konami code enables advanced
  configuration of allowed keys and port.
* **P2P keyboard/mouse add‑on** – start a direct UDP session with a peer
  using the ``p2p`` command. Choose whether you will send your keyboard
  events or mouse events. The other peer should run Keyshare and also
  choose the complementary role. NAT traversal is handled by sending an
  initial UDP packet to the remote address and port; port forwarding is
  usually not required on home networks.

This program is intended for educational experimentation. Sending input
events to another machine gives that machine control over your system.
Only use it with trusted peers and do not leave it running unattended.
"""

import asyncio
import json
import threading
import sys
import uuid
import socket
import platform
import os

import websockets
from pynput.keyboard import Listener, Controller, Key

# ─── CONFIG ────────────────────────────────────────────────────────────────
AdvancedMode    = False
DEFAULT_PORT    = 6969
DEFAULT_ALLOWED = {'w','a','s','d','e','space', *map(str, range(10))}
ALLOWED         = DEFAULT_ALLOWED.copy()
INSTANCE_ID     = str(uuid.uuid4())
ctrl            = Controller()
# ─────────────────────────────────────────────────────────────────────────────

class Colors:
    """ANSI colour codes for terminal output."""
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    RED    = '\033[91m'
    BLUE   = '\033[94m'
    RESET  = '\033[0m'

OS          = platform.system()
clients     = set()
outbound    = set()
in_info     = {}
out_info    = {}
paused      = False
loop        = None
PORT        = DEFAULT_PORT
config_version = 1

hs_counter      = 0
hs_futures      = {}
hs_requests     = {}


# ─── Utility functions for the original Keyshare behaviour ────────────────
def validate_ip(addr: str) -> bool:
    """Return True if ``addr`` is a valid IPv4 address or 'localhost'."""
    if addr.lower() == "localhost":
        return True
    try:
        socket.inet_aton(addr)
        return True
    except Exception:
        return False


def prompt_consent() -> None:
    """Display the welcome banner and security warning. Prompt for consent."""
    print(f"{Colors.GREEN}Welcome to Keyshare, developed by Wooldrum.{Colors.RESET}\n"
          f"Detected OS: {OS}")
    if OS == "Darwin":  print(f"{Colors.YELLOW}  macOS: On Mac, you may need to grant Accessibility permissions.{Colors.RESET}")
    if OS == "Linux":   print(f"{Colors.YELLOW}  Linux: On Linux, you may need sudo or uinput permissions.{Colors.RESET}")
    if OS == "Windows": print(f"{Colors.YELLOW}  Windows: On Windows, you may need to run as an administrator.{Colors.RESET}")
    print(f"""
{Colors.YELLOW}WARNING: Keyshare broadcasts your keyboard inputs to peers and can also
share your keyboard or mouse inputs with a single peer via UDP. Both modes
pose inherent risks. Only use this tool with people you trust.{Colors.RESET}
• If streaming/recording, hide this window to avoid exposing your IP.
• Peers see your IP, which may expose you to possible DDoS or location leaks.
• P2P uses raw UDP without encryption—use at your own risk.
Default port: {DEFAULT_PORT}
""")
    if input(f"{Colors.GREEN}Do you consent? (yes/no): {Colors.RESET}").strip().lower() not in ("yes", "y"):
        print(f"{Colors.RED}Consent denied. Exiting.{Colors.RESET}")
        sys.exit(0)


def get_local_ip() -> str:
    """Return the local IP address used to reach the internet."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def input_ip(prompt: str, default: str | None = None) -> str:
    """Prompt for an IP address, validating input."""
    while True:
        val = input(f"{Colors.GREEN}{prompt}{' [' + default + ']' if default else ''}: {Colors.RESET}").strip()
        if not val and default:
            return default
        if validate_ip(val):
            return val
        print(f"{Colors.RED}Invalid IP. Try again.{Colors.RESET}")


def input_peers() -> list[str]:
    """Prompt whether the user is the first person and, if not, gather peer IPs."""
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


def inject(key_name: str, typ: str) -> None:
    """Inject a key press or release locally using pynput."""
    try:
        key_to_press = None
        if hasattr(Key, key_name):
            key_to_press = getattr(Key, key_name)
        else:
            key_to_press = key_name
        if typ == "down":
            ctrl.press(key_to_press)
        else:
            ctrl.release(key_to_press)
    except Exception as e:
        print(f"{Colors.RED}[!] Injection error: {e}{Colors.RESET}")


async def ws_handler(ws, path):
    """Handle inbound WebSocket connections for handshake and key relay."""
    global hs_counter
    try:
        msg = await ws.recv()
        req = json.loads(msg)
        if req.get("type") != "handshake_request":
            return await ws.close()
        user, ip = req.get("username"), req.get("ip")
        hs_counter += 1
        hid = hs_counter
        fut = loop.create_future()
        hs_futures[hid] = fut
        hs_requests[hid] = (ws, user, ip)
        print(f"\n{Colors.YELLOW}[!] Connection Request ({hid}): {user} at {ip} would like to join.\n"
              f"    To accept, type 'allow {hid}'. To reject, type 'deny {hid}'.{Colors.RESET}")
        allow = await fut
        del hs_futures[hid], hs_requests[hid]
        if not allow:
            await ws.send(json.dumps({"type": "handshake_response", "allow": False}))
            await ws.close()
            return
        response = {"type": "handshake_response", "allow": True,
                    "allowed_keys": list(ALLOWED), "config_version": config_version}
        await ws.send(json.dumps(response))
        clients.add(ws)
        in_info[ws] = (user, ip)
        print(f"{Colors.GREEN}[+] in: {user}[{ip}]{Colors.RESET}")
        async for raw in ws:
            d = json.loads(raw)
            if d.get("origin") == INSTANCE_ID:
                continue
            if not paused:
                inject(d["key"], d["type"])
            await broadcast(d, exclude={ws})
    except websockets.ConnectionClosed:
        pass
    finally:
        if ws in clients:
            user, ip = in_info.pop(ws, ("?", "?"))
            print(f"{Colors.BLUE}[-] disconnected: {user}[{ip}]{Colors.RESET}")
            clients.discard(ws)


async def connect(peers: list[str], local_ip: str, uname: str) -> None:
    """Connect to remote peers specified at startup."""
    global ALLOWED, config_version
    for addr in peers:
        uri = f"ws://{addr}:{PORT}"
        try:
            ws = await websockets.connect(uri)
            await ws.send(json.dumps({"type": "handshake_request", "username": uname, "ip": local_ip}))
            res_raw = await ws.recv()
            res = json.loads(res_raw)
            if res.get("type") == "handshake_response" and res.get("allow"):
                new_allowed = set(res.get('allowed_keys', DEFAULT_ALLOWED))
                consent_given = True
                if new_allowed != ALLOWED:
                    print(f"\n{Colors.YELLOW}WARNING: The host ({addr}) is using custom key settings.{Colors.RESET}")
                    print(f"{Colors.YELLOW}The following keys will be shared: {', '.join(sorted(list(new_allowed)))}{Colors.RESET}")
                    while True:
                        confirm = input(f"{Colors.GREEN}Proceed with these settings? (yes/no): {Colors.RESET}").strip().lower()
                        if confirm in ('yes', 'y'):
                            break
                        elif confirm in ('no', 'n'):
                            consent_given = False
                            break
                        else:
                            print(f"{Colors.RED}Invalid input. Please enter 'yes' or 'no'.{Colors.RESET}")
                if not consent_given:
                    print(f"{Colors.RED}Connection to {addr} cancelled.{Colors.RESET}")
                    await ws.close()
                    continue
                outbound.add(ws)
                out_info[ws] = addr
                ALLOWED = new_allowed
                config_version = res.get('config_version', 1)
                print(f"{Colors.GREEN}[+] out: {addr}{Colors.RESET}")
                if new_allowed != DEFAULT_ALLOWED:
                    print(f"{Colors.BLUE}Key settings synced with host.{Colors.RESET}")
                asyncio.create_task(handle_peer(ws, addr))
            else:
                print(f"{Colors.RED}[-] out denied: {addr}{Colors.RESET}")
                await ws.close()
        except Exception as e:
            print(f"{Colors.RED}[!] Connection to {addr} failed: {e}{Colors.RESET}")


async def handle_peer(ws, addr: str) -> None:
    """Handle messages from an outbound peer after handshake."""
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
            if d.get("origin") == INSTANCE_ID:
                continue
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


async def broadcast(msg: dict, exclude: set | None = None) -> None:
    """Send a message to all connected clients except those in ``exclude``."""
    targets = (clients | outbound) - (exclude or set())
    if targets:
        data = json.dumps(msg)
        tasks = [w.send(data) for w in targets]
        await asyncio.gather(*tasks, return_exceptions=True)


def get_key_name(key):
    """Normalise a pynput key into a lowercase string name."""
    if isinstance(key, str):
        return key
    if isinstance(key, Key):
        return key.name
    if hasattr(key, 'char') and key.char:
        return key.char.lower()
    return None


def handle_key(k, typ: str) -> None:
    """Handle a key event from the local keyboard and broadcast it if allowed."""
    if paused or not loop:
        return
    key_name = get_key_name(k)
    if key_name in ALLOWED:
        pkt = {"origin": INSTANCE_ID, "key": key_name, "type": typ}
        asyncio.run_coroutine_threadsafe(broadcast(pkt), loop)


def on_press(k):
    handle_key(k, "down")


def on_release(k):
    handle_key(k, "up")


def start_hook() -> None:
    """Start a blocking listener for the local keyboard using pynput."""
    with Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()


def cmd_loop() -> None:
    """Read commands from stdin and control the program accordingly."""
    global paused, loop, ALLOWED, config_version
    base_cmds = {"pause", "resume", "stop", "peers", "allow", "deny", "p2p"}
    while True:
        try:
            current_cmds = base_cmds.copy()
            if AdvancedMode:
                current_cmds.add("edit")
            line = input().strip().split()
            if not line:
                continue
            cmd = line[0].lower()
            # pause/resume/stop
            if cmd == "pause":
                print(f"{Colors.YELLOW}== paused =={Colors.RESET}")
                paused = True
            elif cmd == "resume":
                print(f"{Colors.YELLOW}== resumed =={Colors.RESET}")
                paused = False
            elif cmd in ("stop", "exit", "quit"):
                print(f"{Colors.RED}== stopping =={Colors.RESET}")
                if loop:
                    loop.call_soon_threadsafe(loop.stop)
                break
            # list peers
            elif cmd == "peers":
                ins = [f"{in_info[w][0]}[{in_info[w][1]}]" for w in clients]
                outs = [out_info[w] for w in outbound]
                print(f"{Colors.BLUE}IN:{Colors.RESET} {ins or 'none'}\n{Colors.BLUE}OUT:{Colors.RESET} {outs or 'none'}")
            # allow/deny handshake
            elif cmd in ("allow", "deny") and len(line) == 2 and line[1].isdigit():
                hid = int(line[1])
                fut = hs_futures.get(hid)
                if fut and not fut.done():
                    fut.set_result(cmd == "allow")
                    print(f"{Colors.GREEN if cmd == 'allow' else Colors.RED}Request #{hid} has been {'allowed' if cmd == 'allow' else 'denied'}.{Colors.RESET}")
                else:
                    print(f"{Colors.RED}No pending request #{hid}{Colors.RESET}")
            # edit allowed keys (advanced mode)
            elif AdvancedMode and cmd == "edit":
                print(f"{Colors.YELLOW}== Pausing for edit =={Colors.RESET}")
                paused = True
                new_keys = input_allowed_keys()
                if new_keys != ALLOWED:
                    ALLOWED = new_keys
                    config_version += 1
                    print(f"{Colors.BLUE}Broadcasting updated settings to peers...{Colors.RESET}")
                    update_msg = {"type": "config_update", "allowed_keys": list(ALLOWED), "config_version": config_version}
                    asyncio.run_coroutine_threadsafe(broadcast(update_msg), loop)
                print(f"{Colors.YELLOW}== Resuming =={Colors.RESET}")
                paused = False
            # p2p command to start peer-to-peer mode
            elif cmd == "p2p":
                print(f"{Colors.BLUE}== Starting P2P mode =={Colors.RESET}")
                try:
                    start_p2p()
                except Exception as e:
                    print(f"{Colors.RED}[!] P2P error: {e}{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}cmds:{Colors.RESET} ", ", ".join(sorted(list(current_cmds))))
        except (EOFError, KeyboardInterrupt):
            if loop:
                loop.call_soon_threadsafe(loop.stop)
            break


def konami_listener(activated_event: threading.Event, startup_finished_event: threading.Event) -> None:
    """Listen for the Konami code to activate advanced mode while starting up."""
    KONAMI_CODE = [Key.up, Key.up, Key.down, Key.down, Key.left, Key.right, Key.left, Key.right, 'b', 'a']
    code_keys = [get_key_name(k) for k in KONAMI_CODE]
    recent_keys: list[str] = []
    def on_press(key):
        nonlocal recent_keys
        if startup_finished_event.is_set() or activated_event.is_set():
            return False
        key_name = get_key_name(key)
        if key_name is None:
            return
        recent_keys.append(key_name)
        if len(recent_keys) > len(code_keys):
            recent_keys.pop(0)
        if recent_keys == code_keys:
            global AdvancedMode
            AdvancedMode = True
            print(f"\n{Colors.YELLOW}** ADVANCED MODE ACTIVATED **{Colors.RESET}")
            activated_event.set()
            return False
    with Listener(on_press=on_press) as l:
        l.join()


def input_allowed_keys() -> set[str]:
    """Prompt the user to edit the set of allowed keys."""
    print(f"{Colors.BLUE}Current allowed keys: {', '.join(sorted(list(ALLOWED)))}{Colors.RESET}")
    while True:
        raw = input(f"{Colors.GREEN}Enter new keys (comma separated), or press ENTER to keep current: {Colors.RESET}").strip()
        if not raw:
            return ALLOWED
        parts = {p.strip().lower() for p in raw.split(",")}
        if all(parts):
            print(f"{Colors.BLUE}New allowed keys set.{Colors.RESET}")
            return parts
        print(f"{Colors.RED}Invalid input. Please provide a comma-separated list of keys.{Colors.RESET}")


# ─── P2P add-on functions ─────────────────────────────────────────────────
def p2p_send_keyboard(sock: socket.socket, peer_addr: tuple[str, int]) -> None:
    """Listen for global keyboard events and send them over UDP to ``peer_addr``."""
    try:
        import keyboard  # type: ignore
    except ImportError:
        print(f"{Colors.RED}[!] The 'keyboard' module is required for P2P keyboard control. Install with `pip install keyboard`.{Colors.RESET}")
        return
    def on_event(event):
        # We only care about key down/up events
        if event.event_type not in ("down", "up"):
            return
        payload = {"type": "p2p_kb", "name": event.name, "event_type": event.event_type}
        try:
            sock.sendto(json.dumps(payload).encode(), peer_addr)
        except Exception as ex:
            print(f"{Colors.RED}[!] P2P send error: {ex}{Colors.RESET}")
    keyboard.hook(on_event)


def p2p_send_mouse(sock: socket.socket, peer_addr: tuple[str, int]) -> None:
    """Listen for global mouse events and send them over UDP to ``peer_addr``."""
    try:
        import mouse  # type: ignore
    except ImportError:
        print(f"{Colors.RED}[!] The 'mouse' module is required for P2P mouse control. Install with `pip install mouse`.{Colors.RESET}")
        return
    # We track the last position to compute deltas
    last_pos = [0, 0]
    def on_move(x, y):
        dx = x - last_pos[0]
        dy = y - last_pos[1]
        last_pos[0], last_pos[1] = x, y
        payload = {"type": "p2p_mouse_move", "dx": dx, "dy": dy}
        try:
            sock.sendto(json.dumps(payload).encode(), peer_addr)
        except Exception as ex:
            print(f"{Colors.RED}[!] P2P send error: {ex}{Colors.RESET}")
    def on_click(x, y, button, pressed):
        # button may be an enum or string; normalise to string
        bname = button.name if hasattr(button, 'name') else str(button)
        payload = {"type": "p2p_mouse_click", "button": bname, "pressed": pressed}
        try:
            sock.sendto(json.dumps(payload).encode(), peer_addr)
        except Exception as ex:
            print(f"{Colors.RED}[!] P2P send error: {ex}{Colors.RESET}")
    def on_scroll(x, y, dx, dy):
        payload = {"type": "p2p_mouse_scroll", "dx": dx, "dy": dy}
        try:
            sock.sendto(json.dumps(payload).encode(), peer_addr)
        except Exception as ex:
            print(f"{Colors.RED}[!] P2P send error: {ex}{Colors.RESET}")
    # register handlers
    mouse.on_move(on_move)
    mouse.on_click(on_click)
    mouse.on_scroll(on_scroll)


def p2p_receive(sock: socket.socket) -> None:
    """Receive UDP messages and replay keyboard/mouse events locally."""
    try:
        import pyautogui  # type: ignore
    except ImportError:
        print(f"{Colors.RED}[!] The 'pyautogui' module is required to receive P2P events. Install with `pip install pyautogui`.{Colors.RESET}")
        return
    while True:
        try:
            data, _ = sock.recvfrom(4096)
            msg = json.loads(data.decode())
            typ = msg.get("type")
            if typ == "p2p_kb":
                name = msg.get("name")
                event_type = msg.get("event_type")
                if name is None or event_type not in ("down", "up"):
                    continue
                if event_type == "down":
                    pyautogui.keyDown(name)
                else:
                    pyautogui.keyUp(name)
            elif typ == "p2p_mouse_move":
                dx = msg.get("dx", 0)
                dy = msg.get("dy", 0)
                # moveRel moves relative to current position
                pyautogui.moveRel(dx, dy)
            elif typ == "p2p_mouse_click":
                bname = msg.get("button", "left")
                pressed = msg.get("pressed", False)
                if pressed:
                    pyautogui.mouseDown(button=bname)
                else:
                    pyautogui.mouseUp(button=bname)
            elif typ == "p2p_mouse_scroll":
                dx = msg.get("dx", 0)
                dy = msg.get("dy", 0)
                # pyautogui scrolls vertically; horizontal scrolling not widely supported
                if dy:
                    pyautogui.scroll(dy)
                if dx:
                    pyautogui.hscroll(dx)
        except Exception as e:
            # Print error and continue listening
            print(f"{Colors.RED}[!] P2P receive error: {e}{Colors.RESET}")


def start_p2p() -> None:
    """Prompt the user for P2P details and start sending or receiving events."""
    # Gather remote and local addressing information
    remote_ip = input(f"{Colors.GREEN}Enter peer IP (remote): {Colors.RESET}").strip()
    if not validate_ip(remote_ip):
        print(f"{Colors.RED}Invalid remote IP.{Colors.RESET}")
        return
    try:
        remote_port = int(input(f"{Colors.GREEN}Enter peer UDP port: {Colors.RESET}").strip())
        if not (1 <= remote_port <= 65535):
            raise ValueError
    except Exception:
        print(f"{Colors.RED}Invalid remote port.{Colors.RESET}")
        return
    local_port_input = input(f"{Colors.GREEN}Enter local UDP port [auto]: {Colors.RESET}").strip()
    try:
        local_port = int(local_port_input) if local_port_input else 0
    except Exception:
        print(f"{Colors.RED}Invalid local port.{Colors.RESET}")
        return
    role = input(f"{Colors.GREEN}Select role ('keyboard' or 'mouse'): {Colors.RESET}").strip().lower()
    if role not in ("keyboard", "mouse"):
        print(f"{Colors.RED}Unknown role. Choose 'keyboard' or 'mouse'.{Colors.RESET}")
        return
    # Create UDP socket and bind to local port
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("", local_port))
    except Exception as e:
        print(f"{Colors.RED}[!] Failed to bind UDP socket: {e}{Colors.RESET}")
        return
    peer_addr: tuple[str, int] = (remote_ip, remote_port)
    # NAT punching – send a dummy packet to the remote peer
    try:
        sock.sendto(b"init", peer_addr)
    except Exception as e:
        print(f"{Colors.RED}[!] Failed to contact peer: {e}{Colors.RESET}")
    # Start receiver thread
    threading.Thread(target=p2p_receive, args=(sock,), daemon=True).start()
    # Start sending according to selected role; this call blocks until program exit
    if role == "keyboard":
        p2p_send_keyboard(sock, peer_addr)
    else:
        p2p_send_mouse(sock, peer_addr)


async def main() -> None:
    """Entry point for the asyncio event loop."""
    global loop, PORT, ALLOWED, AdvancedMode
    konami_activated = threading.Event()
    startup_finished = threading.Event()
    konami_thread = threading.Thread(target=konami_listener,
                                     args=(konami_activated, startup_finished),
                                     daemon=True)
    konami_thread.start()
    def consent_input_wrapper(result_container: dict) -> None:
        prompt_consent()
        result_container["done"] = True
    consent_result = {"done": False}
    consent_thread = threading.Thread(target=consent_input_wrapper,
                                     args=(consent_result,),
                                     daemon=True)
    consent_thread.start()
    # Wait until either consent is given or advanced mode is activated
    while not consent_result["done"] and not konami_activated.is_set():
        await asyncio.sleep(0.1)
    if konami_activated.is_set():
        consent_thread.join(timeout=5)
    loop = asyncio.get_running_loop()
    username = input(f"{Colors.GREEN}Username: {Colors.RESET}").strip() or "Anonymous"
    if AdvancedMode:
        while True:
            try:
                p = input(f"{Colors.GREEN}Set port (1024–65535) [default {DEFAULT_PORT}]: {Colors.RESET}").strip()
                PORT = int(p) if p else DEFAULT_PORT
                if 1024 <= PORT <= 65535:
                    break
            except Exception:
                pass
            print(f"{Colors.RED}Invalid port. Try again.{Colors.RESET}")
        ALLOWED = input_allowed_keys()
    print(f"{Colors.BLUE}Using port: {PORT}{Colors.RESET}")
    local_ip = input_ip("Your LAN IP (Press ENTER if this is correct)", default=get_local_ip())
    peers = input_peers()
    # signal that startup has finished, so the Konami listener stops listening
    startup_finished.set()
    konami_thread.join(timeout=1)
    server = await websockets.serve(ws_handler, local_ip, PORT)
    print(f"{Colors.GREEN}✅ Server running on {local_ip}:{PORT}{Colors.RESET}")
    threading.Thread(target=start_hook, daemon=True).start()
    threading.Thread(target=cmd_loop, daemon=True).start()
    if peers:
        asyncio.create_task(connect(peers, local_ip, username))
    # List of available commands to show the user
    ready_cmds = ["pause", "resume", "stop", "peers", "allow", "deny", "p2p"]
    if AdvancedMode:
        ready_cmds.append("edit")
    print(f"{Colors.GREEN}✅ Ready. Commands: {', '.join(ready_cmds)}{Colors.RESET}")
    try:
        await server.wait_closed()
    finally:
        server.close()


if __name__ == "__main__":
    # Enable ANSI colours on Windows terminals
    if OS == "Windows":
        os.system('')
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}Exiting program.{Colors.RESET}")
