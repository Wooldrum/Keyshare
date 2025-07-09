const params = new URLSearchParams(location.search);
const wsUrl = params.get('ws') || `ws://${location.host}`;
const layout = params.get('layout') || 'vertical';

document.body.classList.add(layout === 'horizontal' ? 'layout-horizontal' : 'layout-vertical');

const playersDiv = document.getElementById('players');
const players = {};

function createPlayer(name){
  const p = document.createElement('div');
  p.className = 'player';
  const label = document.createElement('div');
  label.textContent = name;
  p.appendChild(label);
  const keysDiv = document.createElement('div');
  keysDiv.className = 'keys';
  p.appendChild(keysDiv);
  playersDiv.appendChild(p);
  players[name] = {el:p, keysDiv, keys:{}};
}

function getKey(player, key){
  if(!player.keys[key]){
    const k = document.createElement('div');
    k.className = 'key';
    k.textContent = key;
    player.keysDiv.appendChild(k);
    player.keys[key] = k;
  }
  return player.keys[key];
}

const ws = new WebSocket(wsUrl);
ws.onmessage = ev => {
  const d = JSON.parse(ev.data);
  if(d.type === 'players'){
    playersDiv.innerHTML = '';
    for(const u of d.players) createPlayer(u);
    return;
  }
  if(!players[d.user]) createPlayer(d.user);
  const p = players[d.user];
  const el = getKey(p, d.key);
  if(d.type === 'down') el.classList.add('pressed');
  else el.classList.remove('pressed');
};
