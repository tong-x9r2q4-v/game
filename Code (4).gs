/**
 * Buy Buy - GAS backend
 * School/classroom point system. Not a real-money payment processor.
 * Spreadsheet schemas are managed by setup.gs.
 */
var BB = {
  APP_NAME: 'Buy Buy',
  SESSION_TTL: 21600,
  LOGIN_LIMIT: 8,
  LOGIN_WINDOW: 600,
  MAX_AMOUNT: 1000000000,
  MAX_NOTE: 120,
  ROLES: ['user', 'admin', 'boss'],
  SHEETS: {
    users: 'users',
    transactions: 'transactions',
    businesses: 'businesses',
    notices: 'notices',
    audit: 'audit'
  }
};

function doGet() {
  return HtmlService.createHtmlOutputFromFile('index')
    .setTitle('Buy Buy | クラスキャッシュレス')
    .addMetaTag('viewport', 'width=device-width, initial-scale=1, maximum-scale=1');
}

// -----------------------------
// Public API: initial setup/auth
// -----------------------------
function apiGetSetupState() {
  return apiWrap_(function () {
    var props = PropertiesService.getScriptProperties();
    var dbId = props.getProperty('BUYBUY_SPREADSHEET_ID');
    if (!dbId) return { initialized: false, setupRequired: false, message: '先に setup.gs の setupBuyBuy() を実行してください。' };
    var users = readObjects_('users');
    var bossExists = users.some(function (u) { return String(u.role) === 'boss' && String(u.status) !== 'DELETED'; });
    return {
      initialized: true,
      setupRequired: !bossExists && !!props.getProperty('BUYBUY_SETUP_TOKEN_HASH'),
      canLogin: bossExists,
      message: bossExists ? '' : (props.getProperty('BUYBUY_SETUP_TOKEN_HASH') ? '' : '初期セットアップが未完了です。管理者が setupBuyBuy() を再実行してください。')
    };
  });
}

function apiCreateBoss(payload) {
  return apiWrap_(function () {
    payload = payload || {};
    var token = cleanText_(payload.setupToken, 120, false);
    var id = validateUserId_(payload.id);
    var name = validateDisplayName_(payload.name);
    var password = validatePassword_(payload.password);
    var pin = validatePin_(payload.pin);
    var lock = LockService.getScriptLock();
    lock.waitLock(15000);
    try {
      var props = PropertiesService.getScriptProperties();
      var expected = props.getProperty('BUYBUY_SETUP_TOKEN_HASH');
      if (!expected || !constantTimeEqual_(sha256Hex_(token), expected)) throw new Error('セットアップトークンが正しくありません。');
      var users = readObjects_('users');
      if (users.some(function (u) { return String(u.role) === 'boss' && String(u.status) !== 'DELETED'; })) throw new Error('最高管理者はすでに登録されています。');
      if (findUser_(id)) throw new Error('このユーザーIDはすでに使われています。');
      var passwordSalt = randomSalt_();
      var pinSalt = randomSalt_();
      var now = new Date();
      appendObject_('users', {
        id: id,
        display_name: name,
        role: 'boss',
        password_hash: secretHash_(password, passwordSalt),
        password_salt: passwordSalt,
        pin_hash: secretHash_(pin, pinSalt),
        pin_salt: pinSalt,
        pin_version: 2,
        balance: 0,
        status: 'ACTIVE',
        created_at: now,
        updated_at: now
      });
      props.deleteProperty('BUYBUY_SETUP_TOKEN_HASH');
      props.setProperty('BUYBUY_INITIALIZED', '1');
      audit_(id, 'BOOTSTRAP_BOSS', id, '初回最高管理者を登録');
      return createSession_(id);
    } finally {
      lock.releaseLock();
    }
  });
}

function apiLogin(idValue, passwordValue) {
  return apiWrap_(function () {
    var id = validateUserId_(idValue);
    var password = String(passwordValue == null ? '' : passwordValue);
    if (!password || password.length > 128) throw new Error('ユーザーIDまたはパスワードが違います。');
    var cache = CacheService.getScriptCache();
    var throttleKey = 'bb_login_' + sha256Hex_(id).substring(0, 32);
    var attempts = Number(cache.get(throttleKey) || 0);
    if (attempts >= BB.LOGIN_LIMIT) throw new Error('ログイン試行が多すぎます。10分ほど待ってから再試行してください。');
    var user = findUser_(id);
    if (!user || String(user.status) !== 'ACTIVE' || !constantTimeEqual_(secretHash_(password, String(user.password_salt || '')), String(user.password_hash || ''))) {
      cache.put(throttleKey, String(attempts + 1), BB.LOGIN_WINDOW);
      throw new Error('ユーザーIDまたはパスワードが違います。');
    }
    cache.remove(throttleKey);
    return createSession_(id);
  });
}

function apiLogout(token) {
  return apiWrap_(function () {
    if (token) CacheService.getScriptCache().remove(sessionKey_(String(token)));
    return { loggedOut: true };
  });
}

function apiChangeCredentials(token, payload) {
  return apiWrap_(function () {
    var actor = requireUser_(token);
    payload = payload || {};
    var currentPassword = String(payload.currentPassword || '');
    var newPassword = validatePassword_(payload.newPassword);
    var newPin = validatePin_(payload.newPin);
    if (!constantTimeEqual_(secretHash_(currentPassword, String(actor.password_salt)), String(actor.password_hash))) throw new Error('現在のパスワードが正しくありません。');
    var lock = LockService.getScriptLock(); lock.waitLock(15000);
    try {
      var latest = findUser_(actor.id);
      if (!latest || latest.status !== 'ACTIVE') throw new Error('アカウントが利用できません。');
      var pSalt = randomSalt_(), pinSalt = randomSalt_();
      setFields_('users', latest.__row, {
        password_hash: secretHash_(newPassword, pSalt), password_salt: pSalt,
        pin_hash: secretHash_(newPin, pinSalt), pin_salt: pinSalt, pin_version: 2, updated_at: new Date()
      });
      audit_(actor.id, 'CHANGE_CREDENTIALS', actor.id, 'パスワードとPINを変更');
      CacheService.getScriptCache().remove(sessionKey_(String(token)));
      return { changed: true };
    } finally { lock.releaseLock(); }
  });
}

// -----------------------------
// Main dashboard / directory
// -----------------------------
function apiGetDashboard(token) {
  return apiWrap_(function () {
    var actor = requireUser_(token);
    var user = publicUser_(actor);
    var txs = readObjects_('transactions').filter(function (t) {
      return String(t.from_id) === actor.id || String(t.to_id) === actor.id || (String(t.actor_id) === actor.id && ['ADMIN_CHARGE', 'STORE_SETTLEMENT'].indexOf(String(t.type)) >= 0);
    }).sort(byDateDesc_).slice(0, 30).map(publicTransaction_);
    var notices = readObjects_('notices').filter(function (n) { return String(n.active) !== 'FALSE' && String(n.active) !== '0'; }).sort(byDateDesc_).slice(0, 8).map(publicNotice_);
    var directory = readObjects_('users').filter(function (u) { return String(u.status) === 'ACTIVE' && String(u.id) !== actor.id; }).map(function (u) {
      return { id: String(u.id), name: String(u.display_name), role: String(u.role) };
    }).sort(function (a, b) { return a.name.localeCompare(b.name, 'ja'); });
    var businesses = readObjects_('businesses').filter(function (s) { return String(s.status) === 'ACTIVE'; }).map(function (s) { var p = publicBusiness_(s); p.canOperate = String(s.owner_id) === actor.id || String(s.member_ids || '').split(',').indexOf(actor.id) >= 0; p.isOwner = String(s.owner_id) === actor.id; return p; });
    return {
      user: user,
      transactions: txs,
      notices: notices,
      directory: directory,
      businesses: businesses,
      pendingCount: 0
    };
  });
}

function apiSendMoney(token, payload) {
  return apiWrap_(function () {
    var actor = requireUser_(token); payload = payload || {};
    var targetId = validateUserId_(payload.toId);
    var amount = validateAmount_(payload.amount);
    var note = cleanText_(payload.note, BB.MAX_NOTE, true);
    var pin = validatePinForUser_(actor, payload.pin);
    verifyPin_(actor, pin);
    if (targetId === actor.id) throw new Error('自分自身には送金できません。');
    var lock = LockService.getScriptLock(); lock.waitLock(15000);
    try {
      var sender = requireActiveUserFresh_(actor.id);
      var receiver = findUser_(targetId);
      if (!receiver || receiver.status !== 'ACTIVE') throw new Error('送金先のユーザーが見つかりません。');
      if (Number(sender.balance) < amount) throw new Error('残高が不足しています。');
      setFields_('users', sender.__row, { balance: Number(sender.balance) - amount, updated_at: new Date() });
      setFields_('users', receiver.__row, { balance: Number(receiver.balance) + amount, updated_at: new Date() });
      appendTransaction_('TRANSFER', actor.id, targetId, amount, note, '', 'COMPLETED', actor.id);
      audit_(actor.id, 'TRANSFER', targetId, '送金ポイント: ' + amount);
      return { message: receiver.display_name + ' さんに送金しました。', balance: Number(sender.balance) - amount };
    } finally { lock.releaseLock(); }
  });
}


// -----------------------------
// Store purchases and settlement
// -----------------------------
function apiPayStore(token, payload) {
  return apiWrap_(function () {
    var actor = requireUser_(token); payload = payload || {};
    var storeId = cleanText_(payload.storeId, 80, false);
    var amount = validateAmount_(payload.amount);
    var pin = validatePinForUser_(actor, payload.pin); verifyPin_(actor, pin);
    var note = cleanText_(payload.note, BB.MAX_NOTE, true);
    var lock = LockService.getScriptLock(); lock.waitLock(15000);
    try {
      var buyer = requireActiveUserFresh_(actor.id);
      var store = findRecord_('businesses', 'store_id', storeId);
      if (!store || String(store.status) !== 'ACTIVE') throw new Error('利用できる店舗が見つかりません。');
      if (String(store.owner_id) === actor.id || String(store.member_ids || '').split(',').indexOf(actor.id) >= 0) throw new Error('担当登録されている自分の店舗では購入できません。');
      if (Number(buyer.balance) < amount) throw new Error('残高が不足しています。');
      setFields_('users', buyer.__row, { balance: Number(buyer.balance) - amount, updated_at: new Date() });
      setFields_('businesses', store.__row, { total_sales: Number(store.total_sales || 0) + amount, updated_at: new Date() });
      appendTransaction_('STORE_PURCHASE', actor.id, 'STORE:' + storeId, amount, note, storeId, 'COMPLETED', actor.id);
      audit_(actor.id, 'STORE_PURCHASE', storeId, '店舗購入ポイント: ' + amount);
      return { message: store.store_name + ' で購入しました。', balance: Number(buyer.balance) - amount };
    } finally { lock.releaseLock(); }
  });
}


function apiCreateStorePaymentRequest(token, payload) {
  return apiWrap_(function () {
    var actor = requireUser_(token); payload = payload || {};
    var storeId = cleanText_(payload.storeId, 80, false);
    var customerId = validateUserId_(payload.customerId);
    var amount = validateAmount_(payload.amount);
    var note = cleanText_(payload.note, BB.MAX_NOTE, true);
    var lock = LockService.getScriptLock(); lock.waitLock(15000);
    try {
      requireActiveUserFresh_(actor.id);
      var store = findRecord_('businesses', 'store_id', storeId);
      if (!store || String(store.status) !== 'ACTIVE') throw new Error('店舗が利用できません。');
      var allowed = String(store.owner_id) === actor.id || String(store.member_ids || '').split(',').indexOf(actor.id) >= 0 || String(actor.role) === 'boss';
      if (!allowed) throw new Error('この店舗で決済を作成する権限がありません。');
      if (String(store.owner_id) === customerId || String(store.member_ids || '').split(',').indexOf(customerId) >= 0) throw new Error('この店舗の担当者には請求できません。');
      var customer = findUser_(customerId);
      if (!customer || String(customer.status) !== 'ACTIVE') throw new Error('顧客が見つからないか利用停止中です。');
      var txId = newId_('tx');
      appendTransactionWithId_(txId, 'STORE_PAYMENT_REQUEST', 'STORE:' + storeId, customerId, amount, note || ('店舗支払い: ' + String(store.store_name || '')), storeId, 'PENDING', actor.id);
      audit_(actor.id, 'STORE_PAYMENT_REQUEST', customerId, '店舗=' + storeId + ' / 金額=' + amount + ' / tx=' + txId);
      return { message: customer.display_name + ' さんに支払い確認を送りました。顧客が「受け取る」画面で内容を確認し、PINを入力すると決済されます。', transactionId: txId };
    } finally { lock.releaseLock(); }
  });
}

function apiAcceptStorePayment(token, transactionIdValue, pinValue) {
  return apiWrap_(function () {
    var actor = requireUser_(token);
    var txId = cleanText_(transactionIdValue, 100, false);
    var pin = validatePinForUser_(actor, pinValue); verifyPin_(actor, pin);
    var lock = LockService.getScriptLock(); lock.waitLock(15000);
    try {
      var customer = requireActiveUserFresh_(actor.id);
      var tx = findRecord_('transactions', 'tx_id', txId);
      if (!tx || String(tx.type) !== 'STORE_PAYMENT_REQUEST' || String(tx.status) !== 'PENDING' || String(tx.to_id) !== actor.id) throw new Error('受け取れる店舗決済が見つかりません。');
      var amount = validateAmount_(tx.amount);
      var storeId = String(tx.related_id || '').trim();
      var store = findRecord_('businesses', 'store_id', storeId);
      if (!store || String(store.status) !== 'ACTIVE') throw new Error('店舗が利用できません。');
      if (Number(customer.balance) < amount) throw new Error('残高が不足しています。');
      setFields_('users', customer.__row, { balance: Number(customer.balance) - amount, updated_at: new Date() });
      setFields_('businesses', store.__row, { total_sales: Number(store.total_sales || 0) + amount, updated_at: new Date() });
      setFields_('transactions', tx.__row, { type: 'STORE_PURCHASE', status: 'COMPLETED' });
      audit_(actor.id, 'STORE_PAYMENT_ACCEPTED', storeId, '店舗=' + storeId + ' / 金額=' + amount + ' / tx=' + txId);
      return { message: String(store.store_name || '店舗') + ' への支払いが完了しました。', balance: Number(customer.balance) - amount };
    } finally { lock.releaseLock(); }
  });
}

function apiSubmitStoreSales(token, payload) {
  return apiWrap_(function () {
    var actor = requireUser_(token); payload = payload || {};
    var storeId = cleanText_(payload.storeId, 80, false);
    var pin = validatePinForUser_(actor, payload.pin); verifyPin_(actor, pin);
    var lock = LockService.getScriptLock(); lock.waitLock(15000);
    try {
      requireActiveUserFresh_(actor.id);
      var store = findRecord_('businesses', 'store_id', storeId);
      if (!store || String(store.status) !== 'ACTIVE') throw new Error('店舗が見つかりません。');
      if (String(actor.role) !== 'boss' && String(store.owner_id) !== actor.id) throw new Error('売上の振込はオーナーのみ実行できます。');
      var amount = Math.floor(Number(store.total_sales || 0));
      if (!Number.isSafeInteger(amount) || amount <= 0) throw new Error('精算する売上がありません。');
      var owner = findUser_(String(store.owner_id));
      if (!owner || owner.status !== 'ACTIVE') throw new Error('店舗オーナーのアカウントが利用できません。');
      setFields_('users', owner.__row, { balance: Number(owner.balance) + amount, updated_at: new Date() });
      setFields_('businesses', store.__row, { total_sales: 0, updated_at: new Date() });
      appendTransaction_('STORE_SETTLEMENT', 'STORE:' + storeId, owner.id, amount, '店舗売上の一括精算: ' + store.store_name, storeId, 'COMPLETED', actor.id);
      audit_(actor.id, 'STORE_SETTLEMENT', storeId, 'オーナー ' + owner.id + ' へ精算: ' + amount);
      return { message: '売上 ' + amount + ' 億をオーナー口座へ振り込みました。', settled: amount };
    } finally { lock.releaseLock(); }
  });
}

function apiGetBusinessDashboard(token) {
  return apiWrap_(function () {
    var actor = requireUser_(token);
    var allStores = readObjects_('businesses').filter(function (s) {
      return String(s.status) === 'ACTIVE' && (String(s.owner_id) === actor.id || String(s.member_ids || '').split(',').indexOf(actor.id) >= 0);
    });
    var txs = readObjects_('transactions').filter(function (t) {
      return String(t.type) === 'STORE_PURCHASE' && allStores.some(function (store) { return String(store.store_id) === String(t.related_id); });
    });
    var now = new Date();
    var todayKey = dateKey_(now);
    var monthKey = Utilities.formatDate(now, Session.getScriptTimeZone(), 'yyyy-MM');
    var sevenDays = [];
    for (var i = 6; i >= 0; i--) {
      var d = new Date(now.getFullYear(), now.getMonth(), now.getDate() - i);
      var key = dateKey_(d);
      var total = txs.reduce(function (sum, t) { return dateKey_(asDate_(t.created_at)) === key ? sum + Number(t.amount || 0) : sum; }, 0);
      sevenDays.push({ date: key, label: Utilities.formatDate(d, Session.getScriptTimeZone(), 'M/d'), total: total });
    }
    var stores = allStores.map(function (s) {
      var storeTx = txs.filter(function (t) { return String(t.related_id) === String(s.store_id); });
      var today = storeTx.reduce(function (sum, t) { return dateKey_(asDate_(t.created_at)) === todayKey ? sum + Number(t.amount || 0) : sum; }, 0);
      var month = storeTx.reduce(function (sum, t) { return Utilities.formatDate(asDate_(t.created_at), Session.getScriptTimeZone(), 'yyyy-MM') === monthKey ? sum + Number(t.amount || 0) : sum; }, 0);
      var owner = findUser_(String(s.owner_id));
      return Object.assign(publicBusiness_(s), { todaySales: today, monthSales: month, ownerName: owner ? String(owner.display_name) : '(不明)' });
    });
    return { stores: stores, weeklySales: sevenDays, canCreate: String(actor.role) === 'boss' };
  });
}

// -----------------------------
// Administrator and boss tools
// -----------------------------
function apiCreateUser(token, payload) {
  return apiWrap_(function () {
    var actor = requireRole_(token, ['boss']); payload = payload || {};
    var id = validateUserId_(payload.id);
    var name = validateDisplayName_(payload.name);
    var role = String(payload.role || 'user').toLowerCase();
    if (BB.ROLES.indexOf(role) < 0 || role === 'boss') throw new Error('作成できる権限は一般社員または管理者です。最高管理者は初回設定で1名を登録します。');
    var password = validatePassword_(payload.password);
    var pin = validatePin_(payload.pin);
    var lock = LockService.getScriptLock(); lock.waitLock(15000);
    try {
      if (findUser_(id)) throw new Error('このユーザーIDはすでに使われています。');
      var pSalt = randomSalt_(), pinSalt = randomSalt_(), now = new Date();
      appendObject_('users', { id: id, display_name: name, role: role, password_hash: secretHash_(password, pSalt), password_salt: pSalt, pin_hash: secretHash_(pin, pinSalt), pin_salt: pinSalt, pin_version: 2, balance: 0, status: 'ACTIVE', created_at: now, updated_at: now });
      audit_(actor.id, 'CREATE_USER', id, 'ユーザー作成 / role=' + role);
      return { message: name + ' さんのアカウントを作成しました。' };
    } finally { lock.releaseLock(); }
  });
}

function apiChargeUser(token, payload) {
  return apiWrap_(function () {
    var actor = requireRole_(token, ['admin', 'boss']); payload = payload || {};
    var targetId = validateUserId_(payload.targetId);
    var amount = validateAmount_(payload.amount);
    var reason = cleanText_(payload.reason, BB.MAX_NOTE, true);
    if (String(actor.role) === 'admin' && targetId === actor.id) throw new Error('管理者は自分自身にチャージできません。');
    var lock = LockService.getScriptLock(); lock.waitLock(15000);
    try {
      requireActiveUserFresh_(actor.id);
      var target = findUser_(targetId);
      if (!target || target.status !== 'ACTIVE') throw new Error('チャージ先のアカウントが利用できません。');
      var txId = newId_('tx');
      appendTransactionWithId_(txId, 'ADMIN_CHARGE', 'SYSTEM', targetId, amount, reason || '管理者からの入金', '', 'PENDING', actor.id);
      audit_(actor.id, 'CHARGE_USER_PENDING', targetId, '受取待ちチャージ: ' + amount + ' / ' + reason + ' / tx=' + txId);
      return { message: target.display_name + ' さんへ ' + amount + ' 億の受取通知を送りました。受取タブで承認すると残高に反映されます。', pending: true, transactionId: txId };
    } finally { lock.releaseLock(); }
  });
}

function apiAcceptCharge(token, transactionIdValue) {
  return apiWrap_(function () {
    var actor = requireUser_(token);
    var txId = cleanText_(transactionIdValue, 100, false);
    var lock = LockService.getScriptLock(); lock.waitLock(15000);
    try {
      var tx = findRecord_('transactions', 'tx_id', txId);
      if (!tx || String(tx.type) !== 'ADMIN_CHARGE' || String(tx.status) !== 'PENDING' || String(tx.to_id) !== actor.id) {
        throw new Error('受け取れるチャージが見つかりません。すでに受取済みの可能性があります。');
      }
      var user = requireActiveUserFresh_(actor.id);
      var amount = validateAmount_(tx.amount);
      var balance = Number(user.balance);
      if (!Number.isSafeInteger(balance) || balance < 0 || balance + amount > Number.MAX_SAFE_INTEGER) throw new Error('残高データが不正です。管理者に確認してください。');
      setFields_('users', user.__row, { balance: balance + amount, updated_at: new Date() });
      setFields_('transactions', tx.__row, { status: 'COMPLETED' });
      appendTransaction_('CHARGE_RECEIVED', 'SYSTEM', actor.id, amount, String(tx.note || '管理者チャージを受取'), txId, 'COMPLETED', actor.id);
      audit_(actor.id, 'ACCEPT_CHARGE', txId, '管理者チャージを受取: ' + amount);
      return { message: amount + ' 億を受け取りました。', balance: balance + amount };
    } finally { lock.releaseLock(); }
  });
}

function apiSetUserStatus(token, payload) {
  return apiWrap_(function () {
    var actor = requireRole_(token, ['boss']); payload = payload || {};
    var targetId = validateUserId_(payload.targetId);
    var action = String(payload.action || '').toUpperCase();
    if (['BAN', 'UNBAN', 'DELETE'].indexOf(action) < 0) throw new Error('不正な操作です。');
    if (targetId === actor.id) throw new Error('自分自身のアカウントは変更できません。');
    var lock = LockService.getScriptLock(); lock.waitLock(15000);
    try {
      var target = findUser_(targetId);
      if (!target || target.status === 'DELETED') throw new Error('対象ユーザーが見つかりません。');
      if (String(target.role) === 'boss') {
        var bosses = readObjects_('users').filter(function (u) { return String(u.role) === 'boss' && String(u.status) === 'ACTIVE'; });
        if (bosses.length <= 1) throw new Error('最後の最高管理者はBAN・削除できません。');
      }
      var status = action === 'BAN' ? 'BANNED' : (action === 'UNBAN' ? 'ACTIVE' : 'DELETED');
      setFields_('users', target.__row, { status: status, updated_at: new Date() });
      audit_(actor.id, action + '_USER', targetId, 'status=' + status);
      return { message: target.display_name + ' さんの状態を ' + status + ' に変更しました。' };
    } finally { lock.releaseLock(); }
  });
}

function apiResetCredentials(token, payload) {
  return apiWrap_(function () {
    var actor = requireRole_(token, ['boss']); payload = payload || {};
    var targetId = validateUserId_(payload.targetId);
    var password = validatePassword_(payload.password);
    var pin = validatePin_(payload.pin);
    var lock = LockService.getScriptLock(); lock.waitLock(15000);
    try {
      var target = findUser_(targetId);
      if (!target || target.status === 'DELETED') throw new Error('対象ユーザーが見つかりません。');
      var pSalt = randomSalt_(), pinSalt = randomSalt_();
      setFields_('users', target.__row, { password_hash: secretHash_(password, pSalt), password_salt: pSalt, pin_hash: secretHash_(pin, pinSalt), pin_salt: pinSalt, pin_version: 2, updated_at: new Date() });
      audit_(actor.id, 'RESET_CREDENTIALS', targetId, 'パスワードとPINを再設定');
      return { message: target.display_name + ' さんの認証情報を再設定しました。' };
    } finally { lock.releaseLock(); }
  });
}

function apiCreateBusiness(token, payload) {
  return apiWrap_(function () {
    var actor = requireRole_(token, ['boss']); payload = payload || {};
    var name = validateStoreName_(payload.name);
    var ownerId = validateUserId_(payload.ownerId);
    var owner = findUser_(ownerId);
    if (!owner || owner.status !== 'ACTIVE') throw new Error('オーナーに指定するユーザーが見つかりません。');
    var memberIds = Array.isArray(payload.memberIds) ? payload.memberIds.map(function (x) { return validateUserId_(x); }) : [];
    memberIds = memberIds.filter(function (id, i, all) { return id !== ownerId && all.indexOf(id) === i; });
    if (memberIds.length > 2) throw new Error('オーナー以外のアクセス担当者は2人までです。');
    memberIds.forEach(function (id) { var member = findUser_(id); if (!member || String(member.status) !== 'ACTIVE') throw new Error('アクセス担当者に指定したユーザーが見つからないか、利用停止中です: ' + id); });
    var lock = LockService.getScriptLock(); lock.waitLock(15000);
    try {
      var id = newId_('biz'); var now = new Date();
      appendObject_('businesses', { store_id: id, store_name: name, owner_id: ownerId, member_ids: memberIds.join(','), total_sales: 0, status: 'ACTIVE', created_at: now, updated_at: now });
      audit_(actor.id, 'CREATE_BUSINESS', id, '店舗作成: ' + name + ' / owner=' + ownerId);
      return { message: '店舗「' + name + '」を作成しました。', storeId: id };
    } finally { lock.releaseLock(); }
  });
}

function apiSetBusinessStatus(token, payload) {
  return apiWrap_(function () {
    var actor = requireRole_(token, ['boss']); payload = payload || {};
    var storeId = cleanText_(payload.storeId, 80, false);
    var action = String(payload.action || '').toUpperCase();
    if (['PAUSE', 'ACTIVATE'].indexOf(action) < 0) throw new Error('不正な操作です。');
    var lock = LockService.getScriptLock(); lock.waitLock(15000);
    try {
      var store = findRecord_('businesses', 'store_id', storeId);
      if (!store) throw new Error('店舗が見つかりません。');
      var status = action === 'PAUSE' ? 'PAUSED' : 'ACTIVE';
      setFields_('businesses', store.__row, { status: status, updated_at: new Date() });
      audit_(actor.id, 'BUSINESS_' + action, storeId, 'status=' + status);
      return { message: '店舗の状態を ' + status + ' に変更しました。' };
    } finally { lock.releaseLock(); }
  });
}

function apiCreateNotice(token, payload) {
  return apiWrap_(function () {
    var actor = requireRole_(token, ['admin', 'boss']); payload = payload || {};
    var title = cleanText_(payload.title, 60, false);
    var message = cleanText_(payload.message, 500, false);
    if (title.length < 1 || message.length < 1) throw new Error('タイトルと本文を入力してください。');
    var lock = LockService.getScriptLock(); lock.waitLock(15000);
    try {
      var id = newId_('notice');
      appendObject_('notices', { notice_id: id, title: title, message: message, created_by: actor.id, created_at: new Date(), active: 'TRUE' });
      audit_(actor.id, 'CREATE_NOTICE', id, 'お知らせを配信: ' + title);
      return { message: 'お知らせを全員へ配信しました。' };
    } finally { lock.releaseLock(); }
  });
}

function apiGetAdminData(token) {
  return apiWrap_(function () {
    var actor = requireRole_(token, ['admin', 'boss']);
    var users = readObjects_('users').filter(function (u) { return String(u.status) !== 'DELETED'; }).map(function (u) {
      return { id: String(u.id), name: String(u.display_name), role: String(u.role), balance: normalizeBalance_(u.balance), status: String(u.status), pinVersion: Number(u.pin_version || 1) };
    }).sort(function (a, b) { return a.name.localeCompare(b.name, 'ja'); });
    var stores = readObjects_('businesses').map(publicBusiness_).sort(function (a, b) { return a.name.localeCompare(b.name, 'ja'); });
    var auditLog = String(actor.role) === 'boss' ? readObjects_('audit').sort(byDateDesc_).slice(0, 100).map(publicAudit_) : [];
    return { users: users, stores: stores, auditLog: auditLog, isBoss: String(actor.role) === 'boss' };
  });
}

function apiDeleteNotice(token, noticeIdValue) {
  return apiWrap_(function () {
    var actor = requireRole_(token, ['boss', 'admin']);
    var noticeId = cleanText_(noticeIdValue, 80, false);
    var notice = findRecord_('notices', 'notice_id', noticeId);
    if (!notice) throw new Error('お知らせが見つかりません。');
    setFields_('notices', notice.__row, { active: 'FALSE' });
    audit_(actor.id, 'HIDE_NOTICE', noticeId, 'お知らせを非表示');
    return { hidden: true };
  });
}

// -----------------------------
// Authentication, validation, DB
// -----------------------------
function apiWrap_(callback) {
  try { return { ok: true, data: callback() }; }
  catch (err) {
    var msg = err && err.message ? String(err.message) : '処理に失敗しました。時間をおいて再試行してください。';
    if (msg.length > 220) msg = '処理に失敗しました。時間をおいて再試行してください。';
    return { ok: false, message: msg };
  }
}

function getDb_() {
  var id = PropertiesService.getScriptProperties().getProperty('BUYBUY_SPREADSHEET_ID');
  if (!id) throw new Error('データベースがありません。setup.gs の setupBuyBuy() を実行してください。');
  return SpreadsheetApp.openById(id);
}

function sheet_(key) {
  var ss = getDb_();
  var name = BB.SHEETS[key] || key;
  var sh = ss.getSheetByName(name);
  if (!sh) throw new Error('シート「' + name + '」がありません。setupBuyBuy() を再実行してください。');
  return sh;
}

function readObjects_(key) {
  var sh = sheet_(key);
  var lastRow = sh.getLastRow(), lastCol = sh.getLastColumn();
  if (lastRow < 2 || lastCol < 1) return [];
  var values = sh.getRange(1, 1, lastRow, lastCol).getValues();
  var headers = values[0].map(function (h) { return String(h); });
  var out = [];
  for (var r = 1; r < values.length; r++) {
    if (values[r].every(function (v) { return v === '' || v === null; })) continue;
    var obj = { __row: r + 1 };
    for (var c = 0; c < headers.length; c++) obj[headers[c]] = values[r][c];
    out.push(obj);
  }
  return out;
}

function findRecord_(key, field, value) {
  var target = String(value);
  var items = readObjects_(key);
  for (var i = 0; i < items.length; i++) if (String(items[i][field]) === target) return items[i];
  return null;
}

function findUser_(id) { return findRecord_('users', 'id', String(id)); }

function appendObject_(key, obj) {
  var sh = sheet_(key);
  var headers = sh.getRange(1, 1, 1, sh.getLastColumn()).getValues()[0].map(function (h) { return String(h); });
  var row = headers.map(function (h) { return Object.prototype.hasOwnProperty.call(obj, h) ? obj[h] : ''; });
  sh.appendRow(row);
  return sh.getLastRow();
}

function setFields_(key, row, fields) {
  var sh = sheet_(key);
  var headers = sh.getRange(1, 1, 1, sh.getLastColumn()).getValues()[0].map(function (h) { return String(h); });
  Object.keys(fields).forEach(function (name) {
    var col = headers.indexOf(name) + 1;
    if (col > 0) sh.getRange(row, col).setValue(fields[name]);
  });
}

function appendTransactionWithId_(txId, type, fromId, toId, amount, note, relatedId, status, actorId) {
  appendObject_('transactions', {
    tx_id: txId, type: type, from_id: fromId, to_id: toId,
    amount: amount, note: cleanText_(note, BB.MAX_NOTE, true), related_id: relatedId || '',
    status: status || 'COMPLETED', created_at: new Date(), actor_id: actorId || ''
  });
  return txId;
}

function appendTransaction_(type, fromId, toId, amount, note, relatedId, status, actorId) {
  appendObject_('transactions', {
    tx_id: newId_('tx'), type: type, from_id: fromId, to_id: toId,
    amount: amount, note: cleanText_(note, BB.MAX_NOTE, true), related_id: relatedId || '',
    status: status || 'COMPLETED', created_at: new Date(), actor_id: actorId || ''
  });
}

function audit_(actorId, action, targetId, details) {
  try {
    appendObject_('audit', {
      audit_id: newId_('log'), actor_id: String(actorId || ''), action: String(action || '').substring(0, 60),
      target_id: String(targetId || '').substring(0, 80), details: cleanText_(details, 300, true), created_at: new Date()
    });
  } catch (err) { console.error('Audit log write failed: ' + (err && err.message ? err.message : err)); }
}

function requireUser_(token) {
  var t = String(token || '');
  if (t.length < 24 || t.length > 200) throw new Error('ログイン期限が切れました。もう一度ログインしてください。');
  var cache = CacheService.getScriptCache();
  var raw = cache.get(sessionKey_(t));
  if (!raw) throw new Error('ログイン期限が切れました。もう一度ログインしてください。');
  var session;
  try { session = JSON.parse(raw); } catch (e) { cache.remove(sessionKey_(t)); throw new Error('ログイン期限が切れました。もう一度ログインしてください。'); }
  var user = findUser_(String(session.id || ''));
  if (!user || String(user.status) !== 'ACTIVE') { cache.remove(sessionKey_(t)); throw new Error('アカウントが無効です。'); }
  return user;
}

function requireActiveUserFresh_(id) {
  var user = findUser_(String(id));
  if (!user || String(user.status) !== 'ACTIVE') throw new Error('アカウントが利用できません。');
  return user;
}

function requireRole_(token, roles) {
  var user = requireUser_(token);
  if (roles.indexOf(String(user.role)) < 0) throw new Error('この操作を実行する権限がありません。');
  return user;
}

function createSession_(userId) {
  var user = findUser_(userId);
  if (!user || user.status !== 'ACTIVE') throw new Error('アカウントが利用できません。');
  var token = Utilities.getUuid().replace(/-/g, '') + Utilities.getUuid().replace(/-/g, '');
  CacheService.getScriptCache().put(sessionKey_(token), JSON.stringify({ id: String(userId), createdAt: Date.now() }), BB.SESSION_TTL);
  return { token: token, user: publicUser_(user), expiresIn: BB.SESSION_TTL };
}

function sessionKey_(token) { return 'bb_session_' + sha256Hex_(String(token)); }
function verifyPin_(user, pin) {
  if (!constantTimeEqual_(secretHash_(pin, String(user.pin_salt || '')), String(user.pin_hash || ''))) throw new Error('暗証番号（PIN）が正しくありません。');
}
function secretHash_(secret, salt) { return sha256Hex_(String(salt) + '|' + String(secret)); }
function sha256Hex_(value) {
  var digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, String(value), Utilities.Charset.UTF_8);
  return digest.map(function (b) { var n = b < 0 ? b + 256 : b; return ('0' + n.toString(16)).slice(-2); }).join('');
}
function randomSalt_() { return Utilities.getUuid().replace(/-/g, '') + Utilities.getUuid().replace(/-/g, ''); }
function constantTimeEqual_(a, b) {
  a = String(a || ''); b = String(b || '');
  var diff = a.length ^ b.length; var max = Math.max(a.length, b.length);
  for (var i = 0; i < max; i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}

function validateUserId_(value) {
  var id = String(value == null ? '' : value).trim().toLowerCase();
  if (!/^[a-z0-9_-]{3,24}$/.test(id)) throw new Error('ユーザーIDは半角英数字・_・-で3〜24文字にしてください。');
  return id;
}
function validateDisplayName_(value) {
  var name = cleanText_(value, 40, false);
  if (name.length < 1) throw new Error('表示名を入力してください。');
  return name;
}
function validateStoreName_(value) {
  var name = cleanText_(value, 50, false);
  if (name.length < 1) throw new Error('店舗名を入力してください。');
  return name;
}
function validatePassword_(value) {
  var p = String(value == null ? '' : value);
  if (p.length < 8 || p.length > 128) throw new Error('パスワードは8〜128文字にしてください。');
  if (/^\s+$/.test(p)) throw new Error('パスワードを入力してください。');
  return p;
}
function validatePin_(value) {
  var pin = String(value == null ? '' : value).trim();
  if (!/^\d{6}$/.test(pin)) throw new Error('新しいPINは数字6桁にしてください。');
  return pin;
}
function validatePinForUser_(user, value) {
  var pin = String(value == null ? '' : value).trim();
  // Existing accounts have no pin_version and retain their prior PIN length until changed.
  if (Number(user && user.pin_version || 1) >= 2) {
    if (!/^\d{6}$/.test(pin)) throw new Error('PINは数字6桁で入力してください。');
  } else if (!/^\d{4,12}$/.test(pin)) {
    throw new Error('現在のPINは数字4〜12桁で入力してください。');
  }
  return pin;
}
function validateAmount_(value) {
  var amount = typeof value === 'number' ? value : Number(String(value == null ? '' : value).trim());
  if (!Number.isSafeInteger(amount) || amount < 1 || amount > BB.MAX_AMOUNT) throw new Error('金額は1〜' + BB.MAX_AMOUNT + 'の整数で入力してください（小数不可）。');
  return amount;
}
function cleanText_(value, maxLength, allowEmpty) {
  var text = String(value == null ? '' : value).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').trim();
  if (text.length > maxLength) text = text.substring(0, maxLength);
  if (!allowEmpty && !text) throw new Error('必須項目を入力してください。');
  // Prevent spreadsheet formula injection for any user-controlled text.
  if (/^[=+\-@]/.test(text)) text = "'" + text;
  return text;
}

function publicUser_(u) {
  return { id: String(u.id), name: String(u.display_name), role: String(u.role), balance: normalizeBalance_(u.balance), status: String(u.status), pinVersion: Number(u.pin_version || 1) };
}
function normalizeBalance_(value) { var n = Number(value); return Number.isFinite(n) && n >= 0 ? Math.floor(n) : 0; }
function publicTransaction_(t) {
  return { id: String(t.tx_id), type: String(t.type), fromId: String(t.from_id || ''), toId: String(t.to_id || ''), amount: Number(t.amount || 0), note: String(t.note || ''), relatedId: String(t.related_id || ''), status: String(t.status || ''), createdAt: formatDateTime_(t.created_at), actorId: String(t.actor_id || '') };
}
function publicRequest_(r) {
  var requester = findUser_(String(r.requester_id));
  var payer = findUser_(String(r.payer_id));
  return { id: String(r.request_id), requesterId: String(r.requester_id), requesterName: requester ? String(requester.display_name) : String(r.requester_id), payerId: String(r.payer_id), payerName: payer ? String(payer.display_name) : String(r.payer_id), amount: Number(r.amount || 0), note: String(r.note || ''), status: String(r.status), createdAt: formatDateTime_(r.created_at) };
}
function publicNotice_(n) { return { id: String(n.notice_id), title: String(n.title || ''), message: String(n.message || ''), createdBy: String(n.created_by || ''), createdAt: formatDateTime_(n.created_at) }; }
function publicBusiness_(s) { return { id: String(s.store_id), name: String(s.store_name || ''), ownerId: String(s.owner_id || ''), memberIds: String(s.member_ids || '').split(',').filter(Boolean), pendingSales: Number(s.total_sales || 0), status: String(s.status || '') }; }
function publicAudit_(a) { return { id: String(a.audit_id || ''), actorId: String(a.actor_id || ''), action: String(a.action || ''), targetId: String(a.target_id || ''), details: String(a.details || ''), createdAt: formatDateTime_(a.created_at) }; }
function byDateDesc_(a, b) { return asDate_(b.created_at).getTime() - asDate_(a.created_at).getTime(); }
function asDate_(value) { if (value instanceof Date && !isNaN(value.getTime())) return value; var d = new Date(value); return isNaN(d.getTime()) ? new Date(0) : d; }
function formatDateTime_(value) { return Utilities.formatDate(asDate_(value), Session.getScriptTimeZone(), 'yyyy/MM/dd HH:mm'); }
function dateKey_(value) { return Utilities.formatDate(asDate_(value), Session.getScriptTimeZone(), 'yyyy-MM-dd'); }
function newId_(prefix) { return String(prefix) + '_' + Utilities.getUuid().replace(/-/g, '').substring(0, 16); }
