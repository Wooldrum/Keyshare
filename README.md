# Keyshare

Keyshare is a Python-based utility that broadcasts keyboard inputs to other computers on the same network in real-time. It creates a peer-to-peer (P2P) session where keystrokes on one machine are instantly mirrored on all connected peer machines. By default, it shares `W`, `A`, `S`, `D`, `E`, `Space`, and numbers `0-9`, but the session host can define a custom set of keys.

-----

## Features

  * **Real-Time P2P Broadcasting**: Instantly sends keystrokes to all connected peers in a synchronized session.
  * **Cross-Platform**: Works on Windows, macOS, and Linux, with specific instructions for each.
  * **Host-Controlled Sessions**: The first person to start a session acts as the host, determining the port and shared keys for everyone.
  * **Automatic Settings Sync**: Clients who join a session automatically adopt the host's key configuration.
  * **Security Confirmation**: Joining a session with custom key settings requires explicit consent after showing which keys will be monitored.
  * **Advanced Mode**: Enter the Konami Code at startup to unlock the ability to set a custom port and define which keys to share.

-----

## ⚠️ Security Warning

This application is designed for use with **trusted private networks only**.

  * **No Encryption**: All keystroke data is broadcast without end-to-end encryption.
  * **IP Address Exposure**: Your local IP address is shared with all peers. This can lead to potential security risks like DDoS attacks if used on an untrusted network.
  * **Malicious Peers**: A malicious peer could potentially monitor your inputs.

Do not use this tool on public or untrusted Wi-Fi networks. **Use at your own risk.**

-----

## Requirements

  * Python 3.x
  * The `websockets` and `pynput` Python libraries.

### Installation

You can install the required libraries using `pip`:

```bash
pip install websockets pynput
```

-----

## How to Use

### 1\. (Optional) Activate Advanced Mode

To unlock custom settings, you must enter the **Konami Code** on your keyboard right after starting the script, before the first prompt appears:
`Up, Up, Down, Down, Left, Right, Left, Right, B, A`

A confirmation message will appear if you've entered it correctly.

### 2\. Run the Script & Complete Setup

Open your terminal or command prompt and run the script:

```bash
python3 keyshare.py
```

You will be prompted for initial setup information:

  * **Permissions**: The script requires elevated privileges to function correctly.
      * **Windows**: Run your terminal as an Administrator.
      * **macOS**: Grant Accessibility permissions in System Settings.
      * **Linux**: You may need to use `sudo`.
  * **Consent**: Type `yes` to agree to the security terms.
  * **Username**: Enter a name to identify yourself to peers.
  * **(Advanced Mode)** **Port**: If in Advanced Mode, you can set a custom port or press Enter for the default.
  * **(Advanced Mode)** **Custom Keys**: If in Advanced Mode, you can define a comma-separated list of keys to share.
  * **Advertised IP**: Defaults to your public IP (if reachable) or LAN IP. This is what you give to peers.
  * **Bind Address**: Defaults to `0.0.0.0` to listen on all interfaces; keep this unless you need to restrict it.
  * **First Person?**:
      * If you are the **first person** starting the session, type `yes`. You are now the host.
      * If you are **joining** an existing session, type `no` and enter the IP address of the host when prompted.

### 3\. Approve Connections (Host)

As the host, when a new user tries to connect, you will see a clear, multi-line prompt in your terminal:
`[!] Connection Request (1): Username at 192.168.1.100 would like to join.`
`      To accept, type 'allow 1'. To reject, type 'deny 1'. `

### 4\. Confirm Custom Settings (Client)

If you connect to a host using custom key settings, the script will pause and warn you. It will list all keys the host has configured and you must type `yes` to accept and proceed.

-----

## Runtime Commands

While the script is running, you can enter commands into the terminal:

  * `pause`: Temporarily stop sending and receiving keystrokes.
  * `resume`: Resume the session after it has been paused.
  * `peers`: Show a list of all currently connected peers.
  * `allow <#>`: Allow a pending connection request with the specified ID number.
  * `deny <#>`: Deny a pending connection request.
  * `stop` / `exit` / `quit`: Disconnect all peers and shut down the script.

-----

## No Router Access? Use an Overlay

If you cannot port forward (dorm, CGNAT, locked router):

  * Install **Tailscale** (or ZeroTier) on all participants.
  * Join the same tailnet/network; everyone gets a 100.x (or 10.x) address.
  * Run Keyshare and share your Tailscale/ZeroTier IP and port. No router changes required.

Tunneling alternatives: `ngrok tcp <port>`, `playit.gg`, or `cloudflared tunnel --url tcp://localhost:<port>` can also expose your session without router access (host runs the tunnel; guests use the provided endpoint).

-----

## To-Do List 📝

  - [ ] **Implement Stream Visualizer Feature**
      - [ ] Add a dedicated WebSocket server to the Python script to broadcast key events.
      - [ ] Make the visualizer server start only when **Advanced Mode** is enabled and after the user agrees to a confirmation prompt.
      - [ ] Ensure the server relays key press/release events for **all** connected players, not just the host, using a clear JSON format (e.g., `{ "user": "Player1", "key": "w", "type": "down" }`).
      - [ ] Create the frontend visualizer files:
          - [ ] **index.html**: A file to structure the display of multiple player keypads.
          - [ ] **style.css**: A stylesheet for the look of the keys, including a "pressed" state.
          - [ ] **script.js**: The core logic to connect to the WebSocket and update the keypad UI in real-time based on incoming data.
      - [ ] Update this README with instructions for using the visualizer as a Browser Source in OBS/Streamlabs.

-----

## License

This project is licensed under the **Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License (CC BY-NC-SA 4.0)**.
