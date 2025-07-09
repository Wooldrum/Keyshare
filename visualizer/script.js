function qp(key){return new URLSearchParams(location.search).get(key);}

const PORT = 6970;
const WS_URL = qp('ws') ||
               (location.hostname ? `ws://${location.hostname}:${PORT}`
                                  : `ws://127.0.0.1:${PORT}`);

console.log('[Overlay] connect ->', WS_URL);
const ws   = new WebSocket(WS_URL);
const root = document.getElementById('root');

/* layout switch */
const layout = (qp('layout') || 'vertical').toLowerCase();
if (layout === 'horizontal'){
  root.classList.add('flex','flex-wrap','gap-6');
}else{
  root.classList.add('flex','flex-col','items-center','gap-6');
}

/* store boards */
const boards = {};

/* build */
const TEMPLATE = [
  ['`','1','2','3','4','5','6','7','8','9','0','-','=',{t:'⌫',c:'wide'}],
  [{t:'Tab',c:'wide'},'Q','W','E','R','T','Y','U','I','O','P','[',']','\\'],
  [{t:'Caps',c:'wider'},'A','S','D','F','G','H','J','K','L',';',"'",{t:'Enter',c:'wider'}],
  [{t:'Shift',c:'widest'},'Z','X','C','V','B','N','M',',','.','/',{t:'Shift',c:'widest'}],
  [{t:'Space',c:'space'}]
];

/* websocket hndlr */
ws.addEventListener('open', ()=>console.log('[Overlay] connected'));
ws.addEventListener('error',e=>console.error('[Overlay] error',e));

ws.addEventListener('message', e=>{
  let m; try{ m=JSON.parse(e.data); }catch{ return; }

  if(m.type==='players'){ m.players.forEach(addBoard); return; }
  if(!boards[m.user]) addBoard(m.user);

  boards[m.user].keys.forEach(el=>{
    if(el.dataset.key===m.key){
      (m.type==='down') ? el.classList.add('pressed')
                        : el.classList.remove('pressed');
    }
  });
});

/* helpers */
function addBoard(user){
  if(boards[user]) return;
  const wrap=document.createElement('div');
  wrap.className='player flex flex-col items-center';
  wrap.innerHTML =
      `<div class="player-title">${user}</div>`+
      `<div class="keyboard">${TEMPLATE.map(rowHTML).join('')}</div>`;
  root.appendChild(wrap);
  boards[user]={ keys: wrap.querySelectorAll('.key') };
}

function rowHTML(r){ return `<div class="row">${r.map(keyHTML).join('')}</div>`; }

function keyHTML(k){
  if(typeof k==='string')
      return `<div class="key" data-key="${k.toLowerCase()}">${k}</div>`;
  return `<div class="key ${k.c}" data-key="${(k.t||'').toLowerCase()}">${k.t}</div>`;
}