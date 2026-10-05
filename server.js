const express = require('express');
const http = require('http');
const path = require('path');
const crypto = require('crypto');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const CHANNEL_COUNT = 60;
const APPEAR_HOLD_MS = 10 * 60 * 1000; // 超過最大值後，「出現中」再保留 10 分鐘才消失
const MAX_LOG = 500; // 每個房間的操作紀錄最多保留筆數（避免伺服器記憶體無限成長）
// 房間密碼規則：剛好 6 個字元，只能是英文大小寫或數字（大小寫視為不同）
const PASSWORD_RE = /^[A-Za-z0-9]{6}$/;
const MAX_ROOM_USERS = 10; // 每間房間最多幾個人（同一個瀏覽器開多個分頁只算一人；管理者不計入）
// 房間沒有任何人在線、也沒有任何進行中的 CH 超過這段時間，就自動刪除（釋放記憶體）
const EMPTY_ROOM_TTL_MS = 6 * 60 * 60 * 1000;

// 管理者密鑰：用來讓網站擁有者強制修改 / 禁止 / 移除別人（只對管理者「目前所在的房間」生效）。
// 建議在 Render 的環境變數設定 ADMIN_KEY，不要用預設值。
const ADMIN_KEY = process.env.ADMIN_KEY || 'change-me-admin-key';

const fs = require('fs');

// 比對管理者密鑰（固定時間比較，避免被逐字猜測）
function isAdminKey(key) {
  if (typeof key !== 'string') return false;
  const a = Buffer.from(key);
  const b = Buffer.from(ADMIN_KEY);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// 首頁：只有網址帶正確 ?admin=密鑰 時，才在頁面裡插入管理者腳本；
// 一般使用者拿到的 index.html 跟 client.js 完全沒有任何管理者相關的程式碼。
const INDEX_PATH = path.join(__dirname, 'public', 'index.html');
app.get(['/', '/index.html'], (req, res) => {
  fs.readFile(INDEX_PATH, 'utf8', (err, html) => {
    if (err) return res.status(500).send('Server error');
    res.set('Cache-Control', 'no-store');
    if (isAdminKey(req.query.admin)) {
      const tag = `<script src="/admin.js?k=${encodeURIComponent(req.query.admin)}"></script>\n`;
      html = html.replace('<script src="client.js"></script>', tag + '<script src="client.js"></script>');
    }
    res.type('html').send(html);
  });
});

// 管理者腳本放在 public 之外，密鑰正確才給，否則一律回 404（看起來就像不存在）
const ADMIN_JS_PATH = path.join(__dirname, 'admin', 'admin.js');
app.get('/admin.js', (req, res) => {
  if (!isAdminKey(req.query.k)) return res.status(404).send('Not Found');
  res.set('Cache-Control', 'no-store');
  res.type('application/javascript').sendFile(ADMIN_JS_PATH);
});

app.use(express.static(path.join(__dirname, 'public'), { index: false }));

let nextTabId = 1;

// 預設 9 個分頁（王名 / 最小值 / 最大值 / 圖片檔名）
const BOSS_PRESETS = [
  { name: '紅寶王',     min: 45,  max: 45,  image: 'red-king.png' },
  { name: '樹妖王',     min: 45,  max: 45,  image: 'tree-demon-king.png' },
  { name: '巨居蟹',     min: 45,  max: 45,  image: 'giant-crab.png' },
  { name: '殭屍猴王',   min: 45,  max: 45,  image: 'zombie-monkey-king.png' },
  { name: '蘑菇王',     min: 40,  max: 60,  image: 'mushroom-king.png' },
  { name: '殭屍蘑菇王', min: 40,  max: 60,  image: 'zombie-mushroom-king.png' },
  { name: '沼澤巨鱷',   min: 45,  max: 45,  image: 'swamp-crocodile.png' },
  { name: '巴洛古',     min: 240, max: 360, image: 'barogu.png' },
  { name: '艾利傑(beta)', min: 45, max: 60,  image: 'elliget.png' },
  { name: '雪毛怪人(beta)', min: 45,  max: 60,  image: 'snow-fur-monster.png' }
];

function createChannel() {
  return {
    state: 'idle',      // idle | counting | appearing
    startTime: null,    // server epoch ms
    customMin: null,    // null = 使用分頁預設值
    customMax: null,
    startedBy: null      // 是誰觸發這次倒數的暱稱
  };
}

function createTab(name, minMinutes, maxMinutes, image, locked) {
  const id = nextTabId++;
  return {
    id,
    name: (name && name.trim()) || `分頁 ${id}`,
    minMinutes: minMinutes || 45,
    maxMinutes: maxMinutes || 60,
    image: image || null,
    locked: !!locked, // 鎖定的分頁：無法刪除、無法修改最小值/最大值
    channels: Array.from({ length: CHANNEL_COUNT }, createChannel)
  };
}

// ---------- 房間 ----------
// 相同「房間密碼」的人會進到同一個房間，共用同一份計時器。
// 房間以密碼的 SHA-256 雜湊當作 key；密碼原文只會傳給通過驗證的管理者（管理者面板的「所有房間」列表）。
const rooms = new Map(); // roomId -> room

function roomIdFromPassword(password) {
  return 'room:' + crypto.createHash('sha256').update(password, 'utf8').digest('hex');
}

function createRoom(id, password) {
  return {
    id,
    password,
    createdAt: Date.now(),
    // 每個新房間都有 9 個預設王分頁（固定鎖定，不可刪除、不可改時間範圍）
    tabs: BOSS_PRESETS.map((b) => createTab(b.name, b.min, b.max, b.image, true)),
    connectedUsers: new Map(),  // socket.id -> nickname
    bannedNicknames: new Set(), // 已被管理者移除、不可再進入此房間的暱稱（小寫）
    mutedNicknames: new Map(),  // 被禁止操作的使用者（小寫暱稱 -> 原始暱稱）
    activityLog: [],
    // 隊長：建立房間的人（以瀏覽器識別碼記住，重新整理、斷線重連後仍是隊長）
    captainClientId: null,
    lastActive: Date.now()
  };
}

function getRoom(socket) {
  const id = socket.data.roomId;
  return id ? rooms.get(id) : null;
}

function normalizeName(name) {
  return (name || '').trim().toLowerCase();
}

function findTab(room, tabId) {
  return room.tabs.find((t) => t.id === tabId);
}

// 管理者在房間裡是「隱身」的：不算在線上人數、不出現在名單，也不佔用暱稱
// （否則一般使用者輸入相同暱稱被擋下，就會發現房間裡有人）。
function isAdminSocketId(socketId) {
  const s = io.sockets.sockets.get(socketId);
  return !!(s && s.data.isAdmin);
}

// joiningIsAdmin = true 時（管理者自己要進房）連其他管理者的暱稱也一起比對；
// 一般使用者只跟一般使用者比對。
// 同一個瀏覽器（clientId 相同）的連線視為「同一個人」：重新整理時舊連線還沒被伺服器偵測到斷線，
// 或同時開兩個分頁，都不會被判定成「暱稱已有人使用」。
function clientIdOf(socketId) {
  const s = io.sockets.sockets.get(socketId);
  return (s && s.data.clientId) || null;
}

function isNicknameTaken(room, name, excludeSocketId, joiningIsAdmin, joiningClientId) {
  const norm = normalizeName(name);
  for (const [id, n] of room.connectedUsers.entries()) {
    if (id === excludeSocketId || normalizeName(n) !== norm) continue;
    if (joiningClientId && clientIdOf(id) === joiningClientId) continue; // 是自己（另一個分頁 / 舊連線）
    if (!joiningIsAdmin && isAdminSocketId(id)) continue;
    return true;
  }
  return false;
}

// 房間內的使用者名單（同一個瀏覽器、同暱稱、同身分的多條連線合併成一人）。
// 「是不是管理者」也是合併條件之一：同一個瀏覽器一個分頁當一般使用者、另一個分頁用 admin 網址時，
// 兩者分開計算，只有 admin 那個隱身，一般使用者照常顯示。
function roomUserList(room) {
  const seen = new Map();
  for (const [id, name] of room.connectedUsers.entries()) {
    const hidden = isAdminSocketId(id);
    const key = (clientIdOf(id) || id) + '|' + normalizeName(name) + '|' + (hidden ? 'admin' : 'user');
    if (!seen.has(key)) seen.set(key, { id, name, hidden });
  }
  return Array.from(seen.values());
}

function isCaptain(room, socket) {
  return !!room.captainClientId && !socket.data.isAdmin && socket.data.clientId === room.captainClientId;
}

// 房間目前「看得見的人數」（同一瀏覽器同暱稱只算一人，管理者不計入）
function visibleUserCount(room) {
  return roomUserList(room).filter((u) => !u.hidden).length;
}

// 跟 targetSocketId 同一個瀏覽器、同一個身分（一般 / 管理者）、在同一個房間的所有連線
// （管理者對一般使用者改名、移除時，不會波及同一個瀏覽器裡的管理者分頁）
function sameClientSocketsInRoom(room, targetSocketId) {
  const target = io.sockets.sockets.get(targetSocketId);
  if (!target || target.data.roomId !== room.id) return [];
  const cid = target.data.clientId;
  if (!cid) return [target];
  const targetIsAdmin = !!target.data.isAdmin;
  return Array.from(io.sockets.sockets.values()).filter(
    (s) => s.data.roomId === room.id && s.data.clientId === cid && !!s.data.isAdmin === targetIsAdmin
  );
}

function broadcastState(room) {
  room.lastActive = Date.now();
  io.to(room.id).emit('state:update', { tabs: room.tabs, serverTime: Date.now() });
  scheduleAdminRooms();
}

function broadcastUsers(room) {
  // 所有人（包含管理者自己）收到的都是同一份「看得見的人」名單，資料裡不會出現隱身相關的欄位
  const visible = roomUserList(room)
    .filter((u) => !u.hidden)
    .map(({ id, name }) => ({ id, name, captain: !!room.captainClientId && clientIdOf(id) === room.captainClientId }));
  io.to(room.id).emit('users:update', visible);
  scheduleAdminRooms();
}

// ---------- 管理者：所有房間列表 ----------
function buildAdminRoomList() {
  return Array.from(rooms.values())
    .map((room) => {
      let activeCount = 0;
      room.tabs.forEach((t) => t.channels.forEach((c) => { if (c.state !== 'idle') activeCount++; }));
      return {
        password: room.password,
        users: roomUserList(room).filter((u) => !u.hidden).map((u) => u.name),
        activeCount,
        createdAt: room.createdAt
      };
    })
    .sort((a, b) => b.users.length - a.users.length || b.activeCount - a.activeCount || b.createdAt - a.createdAt);
}

function sendAdminRooms(socket) {
  socket.emit('admin:rooms', buildAdminRoomList());
}

// 房間狀態變動時，稍微延遲合併後再推送給所有管理者（避免一秒內推很多次）
let adminRoomsTimer = null;
function scheduleAdminRooms() {
  if (adminRoomsTimer) return;
  adminRoomsTimer = setTimeout(() => {
    adminRoomsTimer = null;
    for (const [, s] of io.sockets.sockets) {
      if (s.data.isAdmin) sendAdminRooms(s);
    }
  }, 500);
}

function isMuted(room, socket) {
  return room.mutedNicknames.has(normalizeName(socket.data.nickname));
}

// 被禁止的人嘗試任何操作時，直接擋下並通知他
function guardMuted(room, socket) {
  if (isMuted(room, socket)) {
    socket.emit('error:muted');
    return true;
  }
  return false;
}

function broadcastAdminMutedList(room) {
  const info = Array.from(room.mutedNicknames.values());
  for (const [, s] of io.sockets.sockets) {
    if (s.data.isAdmin && s.data.roomId === room.id) s.emit('admin:mutedList', info);
  }
}

function addLog(room, message, type) {
  const entry = {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    time: Date.now(),
    message,
    type: type || 'user'
  };
  room.activityLog.unshift(entry);
  if (room.activityLog.length > MAX_LOG) room.activityLog.length = MAX_LOG;
  io.to(room.id).emit('log:new', entry);
}

function roomHasActiveChannels(room) {
  return room.tabs.some((t) => t.channels.some((c) => c.state !== 'idle'));
}

// 讓 socket 離開目前所在的房間（換房間或斷線時）
function leaveCurrentRoom(socket) {
  const room = getRoom(socket);
  if (!room) return;
  socket.leave(room.id);
  room.connectedUsers.delete(socket.id);
  room.lastActive = Date.now();
  socket.data.roomId = null;
  broadcastUsers(room);
}

// 每秒檢查所有房間所有 CH 是否跨過 min / max 門檻（自動觸發，不寫入操作紀錄）
// 流程：倒數中 -> (到最小值) 出現中 -> (到最大值後再保留 10 分鐘) 恢復待機
function tick() {
  const now = Date.now();

  for (const room of rooms.values()) {
    let changed = false;

    for (const tab of room.tabs) {
      tab.channels.forEach((ch, idx) => {
        if (ch.state === 'idle' || ch.startTime === null) return;

        const minMs = (ch.customMin ?? tab.minMinutes) * 60000;
        const maxMs = (ch.customMax ?? tab.maxMinutes) * 60000;
        const elapsed = now - ch.startTime;

        if (elapsed >= maxMs + APPEAR_HOLD_MS) {
          ch.state = 'idle';
          ch.startTime = null;
          ch.startedBy = null;
          changed = true;
        } else if (elapsed >= minMs && ch.state !== 'appearing') {
          ch.state = 'appearing';
          changed = true;
          io.to(room.id).emit('channelAlert', { tabId: tab.id, channelIndex: idx });
        }
      });
    }

    if (changed) broadcastState(room);
  }
}

setInterval(tick, 1000);

// 每 10 分鐘清掉「沒人在線、也沒有進行中 CH」且閒置太久的房間
setInterval(() => {
  const now = Date.now();
  for (const [id, room] of rooms.entries()) {
    if (room.connectedUsers.size === 0 && !roomHasActiveChannels(room) && now - room.lastActive > EMPTY_ROOM_TTL_MS) {
      rooms.delete(id);
      scheduleAdminRooms();
    }
  }
}, 10 * 60 * 1000);

io.on('connection', (socket) => {
  // ---------- 進入房間（暱稱 + 房間密碼） ----------
  // 同一個密碼 = 同一個房間；密碼對應的房間不存在時會自動建立。
  socket.on('joinRoom', (payload) => {
    const { nickname, password, clientId } = payload || {};
    if (typeof clientId === 'string' && /^[A-Za-z0-9-]{8,64}$/.test(clientId)) socket.data.clientId = clientId;
    const trimmedName = (typeof nickname === 'string' ? nickname : '').trim().slice(0, 20);
    const pw = (typeof password === 'string' ? password : '').trim();

    if (!trimmedName) {
      socket.emit('join:error', { field: 'nickname', message: '請輸入暱稱' });
      return;
    }
    if (!pw) {
      socket.emit('join:error', { field: 'password', message: '請輸入房間密碼' });
      return;
    }
    if (!PASSWORD_RE.test(pw)) {
      socket.emit('join:error', { field: 'password', message: '房間密碼必須剛好 6 個字元，只能使用英文大小寫或數字' });
      return;
    }

    const roomId = roomIdFromPassword(pw);
    const existing = rooms.get(roomId);

    if (existing) {
      if (existing.bannedNicknames.has(normalizeName(trimmedName))) {
        socket.emit('join:error', { field: 'nickname', code: 'banned', message: '這個暱稱已被管理者移出此房間，請使用其他暱稱' });
        return;
      }
      if (isNicknameTaken(existing, trimmedName, socket.id, !!socket.data.isAdmin, socket.data.clientId)) {
        socket.emit('join:error', { field: 'nickname', code: 'taken', message: '這個暱稱在此房間已經有人在使用，請換一個' });
        return;
      }
      // 人數上限：管理者不受限制；已經在房間裡的同一個人（同瀏覽器、同暱稱，例如重新整理）也不會被擋
      if (!socket.data.isAdmin) {
        const alreadyIn = roomUserList(existing).some(
          (u) => !u.hidden && socket.data.clientId && clientIdOf(u.id) === socket.data.clientId && normalizeName(u.name) === normalizeName(trimmedName)
        );
        if (!alreadyIn && visibleUserCount(existing) >= MAX_ROOM_USERS) {
          socket.emit('join:error', { field: 'password', code: 'full', message: `這個房間已滿（最多 ${MAX_ROOM_USERS} 人），請稍後再試或換一個房間` });
          return;
        }
      }
    }

    // 如果原本在別的房間，先離開
    if (socket.data.roomId && socket.data.roomId !== roomId) leaveCurrentRoom(socket);

    const created = !existing;
    const room = existing || createRoom(roomId, pw);
    if (created) rooms.set(roomId, room);

    socket.join(roomId);
    socket.data.roomId = roomId;
    socket.data.nickname = trimmedName;
    room.connectedUsers.set(socket.id, trimmedName);
    room.lastActive = Date.now();

    // 建立房間的人成為隊長（管理者隱身不當隊長；由管理者建立的房間，第一個進來的一般使用者成為隊長）
    if (!room.captainClientId && !socket.data.isAdmin && socket.data.clientId) {
      room.captainClientId = socket.data.clientId;
    }

    socket.emit('join:ack', { nickname: trimmedName, created, captain: isCaptain(room, socket) });
    socket.emit('state:init', { tabs: room.tabs, serverTime: Date.now() });
    socket.emit('log:init', room.activityLog);
    if (socket.data.isAdmin) socket.emit('admin:mutedList', Array.from(room.mutedNicknames.values()));
    broadcastUsers(room);
  });

  // 產生一組隨機房間密碼（符合規則，且不會跟目前已存在的房間重複）
  socket.on('generateRoomPassword', (cb) => {
    if (typeof cb !== 'function') return;
    const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    for (let attempt = 0; attempt < 50; attempt++) {
      let pw = '';
      for (let i = 0; i < 6; i++) pw += CHARS[crypto.randomInt(CHARS.length)];
      if (!rooms.has(roomIdFromPassword(pw))) return cb(pw);
    }
    cb(null);
  });

  socket.on('leaveRoom', () => {
    leaveCurrentRoom(socket);
  });

  // ---------- 隊長：修改自己或同房間其他人在此房間的暱稱 ----------
  socket.on('captainRename', ({ targetSocketId, newName } = {}) => {
    const room = getRoom(socket);
    if (!room || !isCaptain(room, socket)) return;
    const trimmed = (typeof newName === 'string' ? newName : '').trim().slice(0, 20);
    if (!trimmed) return;
    const targets = sameClientSocketsInRoom(room, targetSocketId).filter((t) => !t.data.isAdmin);
    if (targets.length === 0) return;
    const target = targets[0];
    const oldName = target.data.nickname;
    if (normalizeName(oldName) === normalizeName(trimmed) && oldName === trimmed) return;
    if (room.bannedNicknames.has(normalizeName(trimmed))) {
      socket.emit('error:toast', '這個暱稱已被移出此房間，不能使用');
      return;
    }
    if (isNicknameTaken(room, trimmed, target.id, false, target.data.clientId)) {
      socket.emit('error:toast', '這個暱稱在此房間已經有人在使用');
      return;
    }
    if (room.mutedNicknames.has(normalizeName(oldName))) { // 被禁止的人改名後仍維持禁止
      room.mutedNicknames.delete(normalizeName(oldName));
      room.mutedNicknames.set(normalizeName(trimmed), trimmed);
      broadcastAdminMutedList(room);
    }
    targets.forEach((t) => {
      t.data.nickname = trimmed;
      room.connectedUsers.set(t.id, trimmed);
      t.emit('forceNickname', trimmed);
    });
    broadcastUsers(room);
    const self = target.data.clientId === socket.data.clientId;
    addLog(room, self
      ? `隊長「${oldName}」將自己的暱稱改為「${trimmed}」`
      : `隊長「${socket.data.nickname}」將「${oldName}」的暱稱改為「${trimmed}」`, 'admin');
  });

  // 只用於管理者修改自己的暱稱（一般使用者暱稱設定後無法自行更改）
  socket.on('setNickname', (name) => {
    const room = getRoom(socket);
    if (!room || !socket.data.isAdmin) return;
    const trimmed = (name || '').trim().slice(0, 20);
    if (!trimmed) return;
    if (isNicknameTaken(room, trimmed, socket.id, true, socket.data.clientId)) {
      socket.emit('error:toast', '這個暱稱在此房間已經有人在使用');
      return;
    }
    socket.data.nickname = trimmed;
    room.connectedUsers.set(socket.id, trimmed);
    socket.emit('forceNickname', trimmed);
    broadcastUsers(room);
  });

  // ---------- 管理者驗證 ----------
  socket.on('adminAuth', (key) => {
    const ok = isAdminKey(key);
    socket.data.isAdmin = ok;
    socket.emit('adminAuth:result', ok);
    const room = getRoom(socket);
    if (ok && room) socket.emit('admin:mutedList', Array.from(room.mutedNicknames.values()));
    if (ok) sendAdminRooms(socket);
    if (room) broadcastUsers(room); // 驗證成功後立刻從其他人的線上名單消失
  });

  // 管理者強制修改「同房間、目前仍連線中」某個使用者的暱稱
  socket.on('adminRenameUser', ({ targetSocketId, newName } = {}) => {
    const room = getRoom(socket);
    if (!room || !socket.data.isAdmin) return;
    const trimmed = (newName || '').trim().slice(0, 20);
    if (!trimmed) return;
    const targets = sameClientSocketsInRoom(room, targetSocketId);
    if (targets.length === 0) return;

    const oldName = targets[0].data.nickname;
    if (room.mutedNicknames.has(normalizeName(oldName))) { // 被禁止的人改名後仍維持禁止
      room.mutedNicknames.delete(normalizeName(oldName));
      room.mutedNicknames.set(normalizeName(trimmed), trimmed);
      broadcastAdminMutedList(room);
    }
    targets.forEach((t) => {
      t.data.nickname = trimmed;
      room.connectedUsers.set(t.id, trimmed);
      t.emit('forceNickname', trimmed);
    });
    broadcastUsers(room);
    addLog(room, `管理者將「${oldName}」的暱稱改為「${trimmed}」`, 'admin');
  });

  // 管理者禁止 / 解除禁止某位使用者操作（依暱稱判斷，對方離線後重新連線也一樣有效；只限此房間）
  socket.on('adminMuteUser', ({ nickname } = {}) => {
    const room = getRoom(socket);
    if (!room || !socket.data.isAdmin || !nickname) return;
    room.mutedNicknames.set(normalizeName(nickname), nickname);
    broadcastAdminMutedList(room);
    addLog(room, `管理者禁止「${nickname}」進行任何操作`, 'admin');
  });

  socket.on('adminUnmuteUser', ({ nickname } = {}) => {
    const room = getRoom(socket);
    if (!room || !socket.data.isAdmin || !nickname) return;
    if (room.mutedNicknames.delete(normalizeName(nickname))) {
      broadcastAdminMutedList(room);
      addLog(room, `管理者解除了「${nickname}」的操作禁止`, 'admin');
    }
  });

  // 管理者移除成員：中斷連線 + 禁止該暱稱再進入此房間
  socket.on('adminRemoveUser', ({ targetSocketId, nickname } = {}) => {
    const room = getRoom(socket);
    if (!room || !socket.data.isAdmin || !nickname) return;

    room.bannedNicknames.add(normalizeName(nickname));
    sameClientSocketsInRoom(room, targetSocketId).forEach((t) => {
      t.emit('removedByAdmin');
      leaveCurrentRoom(t);
      t.disconnect(true);
    });
    room.connectedUsers.delete(targetSocketId);
    broadcastUsers(room);
    addLog(room, `管理者將「${nickname}」移出房間`, 'admin');
  });

  // 管理者刪除單筆操作紀錄
  socket.on('adminDeleteLogEntry', (logId) => {
    const room = getRoom(socket);
    if (!room || !socket.data.isAdmin) return;
    const idx = room.activityLog.findIndex((e) => e.id === logId);
    if (idx !== -1) {
      room.activityLog.splice(idx, 1);
      io.to(room.id).emit('log:remove', logId);
    }
  });

  // 管理者清空此房間全部操作紀錄
  socket.on('adminClearLog', () => {
    const room = getRoom(socket);
    if (!room || !socket.data.isAdmin) return;
    room.activityLog = [];
    io.to(room.id).emit('log:clear');
    addLog(room, '管理者清空了所有操作紀錄', 'admin');
  });

  // 以下所有操作都必須先進入房間
  function requireRoom() {
    const room = getRoom(socket);
    if (!room || !socket.data.nickname) {
      socket.emit('error:needNickname');
      return null;
    }
    if (guardMuted(room, socket)) return null;
    return room;
  }

  // ---------- 分頁 ----------
  socket.on('addTab', (name) => {
    const room = requireRoom();
    if (!room) return;
    room.tabs.push(createTab(typeof name === 'string' ? name : '', 45, 60, null, false));
    broadcastState(room);
  });

  socket.on('removeTab', (tabId) => {
    const room = requireRoom();
    if (!room) return;
    const tab = findTab(room, tabId);
    if (!tab || tab.locked) return; // 鎖定的分頁不可刪除
    if (room.tabs.length <= 1) return;
    room.tabs = room.tabs.filter((t) => t.id !== tabId);
    broadcastState(room);
  });

  socket.on('renameTab', ({ tabId, name } = {}) => {
    const room = requireRoom();
    if (!room) return;
    const tab = findTab(room, tabId);
    if (tab && typeof name === 'string' && name.trim()) {
      tab.name = name.trim();
      broadcastState(room);
    }
  });

  socket.on('updateTabRange', ({ tabId, minMinutes, maxMinutes } = {}) => {
    const room = requireRoom();
    if (!room) return;
    const tab = findTab(room, tabId);
    if (!tab || tab.locked) return; // 鎖定的分頁不可修改最小值/最大值
    const min = Number(minMinutes);
    const max = Number(maxMinutes);
    if (Number.isFinite(min) && min > 0) tab.minMinutes = min;
    if (Number.isFinite(max) && max > 0) tab.maxMinutes = max;
    if (tab.maxMinutes < tab.minMinutes) tab.maxMinutes = tab.minMinutes;
    broadcastState(room);
  });

  // ---------- CH 左鍵：idle -> 開始計時；計時中再點 -> 手動提前重置 ----------
  socket.on('channelClick', ({ tabId, channelIndex } = {}) => {
    const room = requireRoom();
    if (!room) return;
    const nickname = socket.data.nickname;
    const tab = findTab(room, tabId);
    if (!tab) return;
    const ch = tab.channels[channelIndex];
    if (!ch) return;

    if (ch.state === 'idle') {
      ch.state = 'counting';
      ch.startTime = Date.now();
      ch.startedBy = nickname;
      addLog(room, `${nickname} 在「${tab.name}」啟動了 CH${channelIndex + 1} 倒數`, 'start');
    } else {
      ch.state = 'idle';
      ch.startTime = null;
      ch.startedBy = null;
      addLog(room, `${nickname} 手動停止了「${tab.name}」CH${channelIndex + 1} 的倒數`, 'stop');
    }
    broadcastState(room);
  });

  // ---------- 進行中頻道列表的「擊殺」按鈕：無論目前倒數中或出現中，立即重新開始倒數 ----------
  socket.on('channelKillNow', ({ tabId, channelIndex } = {}) => {
    const room = requireRoom();
    if (!room) return;
    const nickname = socket.data.nickname;
    const tab = findTab(room, tabId);
    if (!tab) return;
    const ch = tab.channels[channelIndex];
    if (!ch) return;

    ch.customMin = null;
    ch.customMax = null;
    ch.state = 'counting';
    ch.startTime = Date.now();
    ch.startedBy = nickname;
    addLog(room, `${nickname} 擊殺了「${tab.name}」CH${channelIndex + 1}，重新開始倒數`, 'start');
    broadcastState(room);
  });

  // ---------- CH 右鍵：輸入王的「死亡時間」，從那個過去的時刻開始倒數 ----------
  // deathTimeEpoch：由前端（瀏覽器本地時區）算好的絕對時間戳記（毫秒），避免伺服器與使用者時區不同造成誤差
  // deathTimeLabel：純粹給操作紀錄顯示用的「HH:MM」文字
  // 傳 deathTimeEpoch = null 代表清除、恢復待機
  socket.on('channelSetCustom', ({ tabId, channelIndex, deathTimeEpoch, deathTimeLabel } = {}) => {
    const room = requireRoom();
    if (!room) return;
    const nickname = socket.data.nickname;
    const tab = findTab(room, tabId);
    if (!tab) return;
    const ch = tab.channels[channelIndex];
    if (!ch) return;

    if (deathTimeEpoch === null || deathTimeEpoch === undefined) {
      const wasActive = ch.state !== 'idle';
      ch.state = 'idle';
      ch.startTime = null;
      ch.customMin = null;
      ch.customMax = null;
      ch.startedBy = null;
      if (wasActive) {
        addLog(room, `${nickname} 透過右鍵重設了「${tab.name}」CH${channelIndex + 1}（恢復待機）`, 'stop');
        broadcastState(room);
      }
      return;
    }

    let deathMs = Number(deathTimeEpoch);
    if (!Number.isFinite(deathMs)) return;

    const now = Date.now();
    if (deathMs > now) {
      // 防呆：死亡時間不應該在未來（理論上前端已經處理過，這裡再保險一次）
      deathMs -= 24 * 60 * 60 * 1000;
    }

    // 死亡時間直接當作起算點，之後照分頁的最小值/最大值自動計算提醒與重置
    ch.customMin = null;
    ch.customMax = null;
    ch.state = 'counting';
    ch.startTime = deathMs;
    ch.startedBy = nickname;

    const label = typeof deathTimeLabel === 'string' ? deathTimeLabel.slice(0, 10) : '';
    addLog(room, `${nickname} 回報「${tab.name}」CH${channelIndex + 1} 的死亡時間為 ${label}，開始倒數`, 'start');
    broadcastState(room);
  });

  // ---------- CH 中鍵：輸入王的「重生時間」（絕對時刻，通常是未來） ----------
  // 重生時間 = 出生時間 = 起算點 + 最小值，所以起算點 = 重生時間 - 最小值；
  // 之後到重生時間變「出現中」，再照最大值 + 10 分鐘自動恢復待機。
  socket.on('channelSetSpawn', ({ tabId, channelIndex, spawnTimeEpoch, spawnTimeLabel } = {}) => {
    const room = requireRoom();
    if (!room) return;
    const nickname = socket.data.nickname;
    const tab = findTab(room, tabId);
    if (!tab) return;
    const ch = tab.channels[channelIndex];
    if (!ch) return;

    const spawnMs = Number(spawnTimeEpoch);
    if (!Number.isFinite(spawnMs)) return;
    const now = Date.now();
    const DAY = 24 * 60 * 60 * 1000;
    if (spawnMs > now + 7 * DAY || spawnMs < now - DAY) {
      socket.emit('error:toast', '重生時間必須在過去 1 天到未來 7 天之內');
      return;
    }

    ch.customMin = null;
    ch.customMax = null;
    ch.startTime = spawnMs - tab.minMinutes * 60000;
    ch.state = spawnMs <= now ? 'appearing' : 'counting';
    ch.startedBy = nickname;

    const label = typeof spawnTimeLabel === 'string' ? spawnTimeLabel.slice(0, 20) : '';
    addLog(room, `${nickname} 設定「${tab.name}」CH${channelIndex + 1} 的重生時間為 ${label}，開始倒數`, 'start');
    broadcastState(room);
  });

  socket.on('disconnect', () => {
    leaveCurrentRoom(socket);
  });
});

server.listen(PORT, () => {
  console.log(`伺服器已啟動：http://localhost:${PORT}`);
});
