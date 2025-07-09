# Keyshare

Keyshare is a Python-based utility that broadcasts keyboard inputs to other computers on the same network in real-time. It creates a peer-to-peer (P2P) session where keystrokes on one machine are instantly mirrored on all connected peer machines. By default, it shares `W`, `A`, `S`, `D`, `E`, `Space`, and numbers `0-9`, but the session host can define a custom set of keys.

-----

## Features

  * **Real-Time P2P Broadcasting**: Instantly sends keystrokes to all connected peers in a synchronized session.
  * **Stream Visualizer Overlay**: 👁️ Launches a local web server to display all players' keystrokes in real-time, perfect for streaming overlays in OBS or Streamlabs.
  * **Cross-Platform**: Works on Windows, macOS, and Linux, with specific instructions for each.
  * **Host-Controlled Sessions**: The first person to start a session acts as the host, determining the port and shared keys for everyone.
  * **Dynamic Re-Consent**: If the host edits keys mid-session, all clients are paused and must explicitly consent to the new key configuration before resuming.
  * **Advanced Mode**: Enter the Konami Code at startup to unlock the ability to set a custom port, define which keys to share, and configure the visualizer layout.

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
  * A `visualizer` folder containing `index.html`, `style.css`, and `script.js` in the same directory as the script.

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
  * **Enable Visualizer**: Type `yes` to start the local server for the stream overlay.
  * **(Advanced Mode)** **Layout**: If you enabled the visualizer in Advanced Mode, you can choose a `vertical` or `horizontal` layout.
  * **Your LAN IP**: The script will auto-detect your IP. Press Enter to confirm it.
  * **First Person?**:
      * If you are the **first person** starting the session, type `yes`. You are now the host.
      * If you are **joining** an existing session, type `no` and enter the IP address of the host when prompted.

### 3\. Approve Connections (Host)

As the host, when a new user tries to connect, you will see a clear, multi-line prompt in your terminal:
`[!] Connection Request (1): Username at 192.168.1.100 would like to join.`
`      To accept, type 'allow 1'. To reject, type 'deny 1'. `

### 4\. Confirm Setting Changes (Client)

If you connect to a host using custom keys, or if the host edits them mid-session, the script will pause and warn you. It will list all keys the host has configured and you must type `yes` to accept and proceed.

-----

## Using the Stream Visualizer

If you enabled the visualizer, the script will print a URL in the terminal after setup is complete:
`Visualizer ready → http://127.0.0.1:8000/index.html?ws=ws://127.0.0.1:6970&layout=vertical`

**To add this to your stream:**

1.  In OBS or Streamlabs, add a new **Browser Source**.
2.  Copy the URL from your terminal and paste it into the URL field of the Browser Source properties.
3.  Adjust the width and height as needed. The visualizer will now appear in your scene, updating in real-time.

-----

## Runtime Commands

While the script is running, you can enter commands into the terminal:

  * `pause`: Temporarily stop sending and receiving keystrokes.
  * `resume`: Resume the session after it has been paused.
  * `peers`: Show a list of all currently connected peers.
  * `allow <#>`: Allow a pending connection request with the specified ID number.
  * `deny <#>`: Deny a pending connection request.
  * `edit`: (Advanced Mode only) Pause the session and edit the list of shared keys.
  * `stop` / `exit` / `quit`: Disconnect all peers and shut down the script.

-----

## License

This project is licensed under the **Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License (CC BY-NC-SA 4.0)**.
