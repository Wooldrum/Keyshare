// --- DOM Elements ---
const connectionControls = document.getElementById('connection-controls');
const sessionControls = document.getElementById('session-controls');
const hostBtn = document.getElementById('host-btn');
const joinBtn = document.getElementById('join-btn');
const stopBtn = document.getElementById('stop-btn');
const pauseBtn = document.getElementById('pause-btn');
const editKeysBtn = document.getElementById('edit-keys-btn');
const logBox = document.getElementById('log-box');
const peerList = document.getElementById('peer-list');
const usernameInput = document.getElementById('username');
const peerIpInput = document.getElementById('peer_ip');
const enableOverlayCheckbox = document.getElementById('enable-overlay');

// --- Modal Elements ---
const keyEditorModal = document.getElementById('key-editor-modal');
const keyCheckboxes = document.getElementById('key-checkboxes');
const saveKeysBtn = document.getElementById('save-keys-btn');
const closeModalBtn = document.querySelector('.close-button');

// --- Event Listeners ---
hostBtn.addEventListener('click', () => {
    eel.start_hosting(usernameInput.value, enableOverlayCheckbox.checked);
});

joinBtn.addEventListener('click', () => {
    eel.join_session(usernameInput.value, peerIpInput.value, enableOverlayCheckbox.checked);
});

stopBtn.addEventListener('click', () => {
    eel.stop_session();
});

pauseBtn.addEventListener('click', () => {
    const isPaused = !pauseBtn.classList.contains('paused');
    eel.toggle_pause(isPaused);
    setPauseButtonState(isPaused);
});

editKeysBtn.addEventListener('click', async () => {
    const initialKeys = await eel.get_initial_keys()();
    keyCheckboxes.innerHTML = '';
    const allKeys = [
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
        'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
        'space', 'enter', 'shift', 'ctrl', 'alt', 'tab', 'esc'
    ];
    allKeys.forEach(key => {
        const isChecked = initialKeys.includes(key);
        keyCheckboxes.innerHTML += `
            <label>
                <input type="checkbox" value="${key}" ${isChecked ? 'checked' : ''}>
                ${key}
            </label>
        `;
    });
    keyEditorModal.style.display = 'block';
});

closeModalBtn.addEventListener('click', () => {
    keyEditorModal.style.display = 'none';
});

saveKeysBtn.addEventListener('click', () => {
    const selectedKeys = [];
    document.querySelectorAll('#key-checkboxes input:checked').forEach(checkbox => {
        selectedKeys.push(checkbox.value);
    });
    eel.save_keys(selectedKeys);
    keyEditorModal.style.display = 'none';
});

// --- Eel Exposed Functions (JS functions called from Python) ---
eel.expose(logMessage, 'logMessage');
function logMessage(message) {
    const p = document.createElement('p');
    p.className = 'log-message';
    if (message.startsWith('[ERROR]')) {
        p.classList.add('error');
    }
    p.textContent = message;
    logBox.appendChild(p);
    logBox.scrollTop = logBox.scrollHeight;
}

eel.expose(updatePeerList, 'updatePeerList');
function updatePeerList(peers) {
    peerList.innerHTML = '';
    peers.forEach(peer => {
        const li = document.createElement('li');
        li.textContent = peer;
        peerList.appendChild(li);
    });
}

eel.expose(setSessionState, 'setSessionState');
function setSessionState(isActive, isHost) {
    connectionControls.style.display = isActive ? 'none' : 'block';
    sessionControls.style.display = isActive ? 'block' : 'none';
    if (isActive && isHost) {
        editKeysBtn.style.display = 'block';
    } else {
        editKeysBtn.style.display = 'none';
    }
}

eel.expose(setPauseState, 'setPauseState');
function setPauseState(isPaused) {
    logMessage(`Session ${isPaused ? 'paused' : 'resumed'} by host action.`);
    setPauseButtonState(isPaused);
}

eel.expose(askForPermission, 'askForPermission');
function askForPermission(user, ip) {
    return confirm(`User '${user}' at ${ip} would like to join.\n\nAllow connection?`);
}

eel.expose(confirmNewKeys, 'confirmNewKeys');
function confirmNewKeys(host, keys_str) {
    return confirm(`The host (${host}) has changed the key settings.\n\nThe new keys are: ${keys_str}\n\nDo you accept these new settings?`);
}

// --- Helper Functions ---
function setPauseButtonState(isPaused) {
    if (isPaused) {
        pauseBtn.classList.add('paused');
        pauseBtn.textContent = 'Resume';
    } else {
        pauseBtn.classList.remove('paused');
        pauseBtn.textContent = 'Pause';
    }
}