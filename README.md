# Keyshare

Keyshare is a Python-based utility that broadcasts keyboard inputs to other computers on the same network in real-time. It creates a peer-to-peer (P2P) session where specified keystrokes (`W`, `A`, `S`, `D`, `E`, `Space`, and numbers `0-9`) on one machine are instantly mirrored on all connected peer machines.

-----

## ⚠️ Security Warning

This application is designed for use on **trusted private networks only**.

- **No Encryption**: All keystroke data is broadcast without end-to-end encryption.  
- **IP Address Exposure**: Your local IP address is shared with all peers. This can lead to potential security risks like DDoS attacks if used on an untrusted network.  
- **Malicious Peers**: A malicious peer could potentially monitor your inputs.

Do not use this tool on public or untrusted Wi-Fi networks. **Use at your own risk.**

-----

## Requirements

- Python 3.x  
- The `websockets` and `pynput` Python libraries.

### Installation

You can install the required libraries using pip:

    pip install -r requirements.txt

Or, if you don't have a `requirements.txt` file, install them manually:

    pip install websockets pynput

-----

## How to Use

1. **Run the Script**  
   Open your terminal or command prompt and run the script:  

       python3 keyshare.py

   You may need to run with elevated privileges for the keyboard listener to work correctly:  
   - **Windows**: Run Command Prompt as an Administrator.  
   - **macOS**: Grant Accessibility permissions to your terminal or IDE.  
   - **Linux**: You may need to use `sudo`.  

2. **Initial Setup (First Peer)**  
   The first time you run it, you'll be prompted for:  
   - **Consent**: Type `yes` to agree to the security terms.  
   - **Username**: Enter a name to identify you to your peers.  
   - **LAN IP**: The script will auto-detect your local IP. You can usually just press Enter.  
   - **Peer IPs**: Since this is the first machine, leave this blank and press Enter.  

3. **Connecting More Peers**  
   - On another computer on the same network, run the script again.  
   - Follow the prompts for consent, username, and IP.  
   - When asked for **Peer IPs**, enter the local IP address of the first machine. You can connect to multiple peers by providing a comma-separated list of their IP addresses.  

4. **Approve Connections**  
   - Back on the first machine's terminal, you will see a connection request.  
   - To approve it, type `allow <#>` (e.g., `allow 1`). To reject it, type `deny <#>` (e.g., `deny 1`).  

5. **Start Sharing!**  
   Once the connection is allowed, the peers are connected. Keystrokes on any connected machine will be broadcast to all others.

-----

## Runtime Commands

While the script is running, you can enter commands into the terminal:

- `pause`: Temporarily stop sending and receiving keystrokes.  
- `resume`: Resume the session after it has been paused.  
- `peers`: Show a list of all currently connected peers.  
- `allow <#>`: Allow a pending connection request with the specified ID number.  
- `deny <#>`: Deny a pending connection request.  
- `stop` / `exit` / `quit`: Disconnect all peers and shut down the script.

-----

## License

This project is licensed under the **Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License (CC BY-NC-SA 4.0)**.

See the LICENSE file for more details.
