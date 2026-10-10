/**
 * Buy Buy database bootstrap.
 * Run setupBuyBuy() once from the Apps Script editor.
 * The generated first-use token is shown in Executions / execution log only once.
 */
var BB_SETUP_SCHEMAS = {
  users: [
    'id', 'display_name', 'role', 'password_hash', 'password_salt', 'pin_hash', 'pin_salt',
    'balance', 'status', 'created_at', 'updated_at'
  ],
  transactions: [
    'tx_id', 'type', 'from_id', 'to_id', 'amount', 'note', 'related_id', 'status', 'created_at', 'actor_id'
  ],
  requests: [
    'request_id', 'requester_id', 'payer_id', 'amount', 'note', 'status', 'created_at', 'updated_at'
  ],
  businesses: [
    'store_id', 'store_name', 'owner_id', 'total_sales', 'status', 'created_at', 'updated_at'
  ],
  notices: [
    'notice_id', 'title', 'message', 'created_by', 'created_at', 'active'
  ],
  audit: [
    'audit_id', 'actor_id', 'action', 'target_id', 'details', 'created_at'
  ]
};

function setupBuyBuy() {
  var props = PropertiesService.getScriptProperties();
  var storedId = props.getProperty('BUYBUY_SPREADSHEET_ID');
  var ss;

  if (storedId) {
    ss = SpreadsheetApp.openById(storedId);
  } else {
    ss = SpreadsheetApp.getActiveSpreadsheet();
    if (!ss) ss = SpreadsheetApp.create('Buy Buy Database');
    props.setProperty('BUYBUY_SPREADSHEET_ID', ss.getId());
  }

  Object.keys(BB_SETUP_SCHEMAS).forEach(function (key) {
    ensureBuyBuySheet_(ss, key, BB_SETUP_SCHEMAS[key]);
  });

  var users = readSetupRows_(ss.getSheetByName('users'));
  var bossExists = users.some(function (u) {
    return String(u.role) === 'boss' && String(u.status) !== 'DELETED';
  });

  var setupToken = '';
  if (!bossExists) {
    setupToken = Utilities.getUuid().replace(/-/g, '') + Utilities.getUuid().replace(/-/g, '');
    props.setProperty('BUYBUY_SETUP_TOKEN_HASH', setupSha256_(setupToken));
    props.deleteProperty('BUYBUY_INITIALIZED');
  } else {
    props.deleteProperty('BUYBUY_SETUP_TOKEN_HASH');
    props.setProperty('BUYBUY_INITIALIZED', '1');
  }

  props.setProperty('BUYBUY_SPREADSHEET_ID', ss.getId());
  Logger.log('=== Buy Buy setup completed ===');
  Logger.log('DATABASE_URL=' + ss.getUrl());
  Logger.log('Database ID=' + ss.getId());
  if (setupToken) {
    Logger.log('ONE_TIME_SETUP_TOKEN=' + setupToken);
    Logger.log('Web app first launch: paste this token into the initial Boss registration screen.');
  } else {
    Logger.log('An active Boss account exists; the initial registration token was not generated.');
  }
  Logger.log('IMPORTANT: Do not share the database spreadsheet with ordinary users.');

  try {
    SpreadsheetApp.getUi().alert(
      'Buy Buy のデータベース準備が完了しました。\n\n' +
      'データベースURLと初回セットアップトークンは、Apps Script の実行ログで確認してください。\n' +
      (setupToken ? '最高管理者の初回登録にトークンが必要です。安全な場所に一時保存してください。' : '最高管理者はすでに登録されています。')
    );
  } catch (ignored) {
    // A standalone Apps Script has no spreadsheet UI; details remain in the execution log.
  }
  return { spreadsheetUrl: ss.getUrl(), firstUseTokenGenerated: !!setupToken };
}

function ensureBuyBuySheet_(ss, name, headers) {
  var sh = ss.getSheetByName(name);
  if (!sh) sh = ss.insertSheet(name);

  var lastRow = sh.getLastRow();
  var lastCol = sh.getLastColumn();
  var isBlank = lastRow === 0 || (lastRow === 1 && lastCol === 0);
  if (isBlank) {
    sh.getRange(1, 1, 1, headers.length).setValues([headers]);
  } else {
    var existing = sh.getRange(1, 1, 1, headers.length).getDisplayValues()[0].map(function (v) { return String(v).trim(); });
    var matches = headers.every(function (h, i) { return existing[i] === h; });
    if (!matches) {
      throw new Error('シート「' + name + '」の列名が想定と異なります。データを消さずに停止しました。列名を確認してください。');
    }
  }

  sh.setFrozenRows(1);
  sh.getRange(1, 1, 1, headers.length)
    .setBackground('#142238')
    .setFontColor('#FFFFFF')
    .setFontWeight('bold')
    .setWrap(true);
  sh.setRowHeight(1, 34);
  sh.autoResizeColumns(1, headers.length);
  if (name === 'users') {
    sh.setColumnWidth(1, 120);
    sh.setColumnWidth(2, 160);
    sh.setColumnWidth(3, 100);
    sh.setColumnWidth(4, 240);
    sh.setColumnWidth(5, 240);
    sh.setColumnWidth(6, 240);
    sh.setColumnWidth(7, 240);
    sh.setColumnWidth(8, 140);
  }
  if (name === 'transactions') {
    sh.setColumnWidth(1, 190);
    sh.setColumnWidth(6, 240);
  }
  if (name === 'audit') {
    sh.setColumnWidth(5, 360);
  }
  return sh;
}

function readSetupRows_(sheet) {
  var lastRow = sheet.getLastRow();
  var lastCol = sheet.getLastColumn();
  if (lastRow < 2 || lastCol < 1) return [];
  var values = sheet.getRange(1, 1, lastRow, lastCol).getValues();
  var headers = values[0].map(function (v) { return String(v); });
  return values.slice(1).filter(function (row) {
    return !row.every(function (v) { return v === '' || v === null; });
  }).map(function (row) {
    var record = {};
    headers.forEach(function (h, i) { record[h] = row[i]; });
    return record;
  });
}

function setupSha256_(value) {
  var digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, String(value), Utilities.Charset.UTF_8);
  return digest.map(function (b) {
    var n = b < 0 ? b + 256 : b;
    return ('0' + n.toString(16)).slice(-2);
  }).join('');
}

function onOpen() {
  try {
    SpreadsheetApp.getUi().createMenu('Buy Buy')
      .addItem('データベースをセットアップ / 再確認', 'setupBuyBuy')
      .addToUi();
  } catch (ignored) {}
}
