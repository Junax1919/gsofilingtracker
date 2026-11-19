/**
 * GSO FILING SYSTEM — Backend (Google Apps Script + Google Sheets)
 *
 * SETUP
 * 1. Create a Google Sheet. Import GSOFILINGRECORDS.xlsx into it as its own tab (optional, for import).
 * 2. Extensions > Apps Script. Paste this file as Code.gs.
 * 3. Run setup()          -> creates Records / Users / AuditLog tabs and the first admin (see Logs for the password).
 * 4. Run importLegacy()   -> (optional) converts your old catalog rows into the Records tab.
 * 5. Deploy > New deployment > Web app. Execute as: Me. Who has access: Anyone.
 *    ("Anyone" is required because index.html runs from your PC; every request is protected by a login session token.)
 * 6. Paste the /exec URL into CONFIG.API_URL in index.html.
 * After editing this file, use Deploy > Manage deployments > Edit > New version.
 */

const CFG = {
  SS_ID: '',               // leave blank when the script is bound to the spreadsheet
    SESSION_SEC: 21600,      // 6 hours (CacheService maximum)
  MAX_FAILS: 5,            // failed logins before lockout
  LOCK_SEC: 900,           // lockout length (15 min)
  ROUNDS: 500              // password hash iterations
};
const T = {REC: 'Records', USR: 'Users', LOG: 'AuditLog'};
const COLS = {
  [T.REC]: ['ID', 'Cabinet', 'Drawer', 'FolderNo', 'FolderName', 'FileNo', 'Description', 'DocType', 'CopyType', 'Remarks',
            'Status', 'CreatedAt', 'CreatedBy', 'UpdatedAt', 'UpdatedBy', 'Version'],
  [T.USR]: ['Username', 'FullName', 'Role', 'Cabinets', 'Status', 'Salt', 'Hash', 'CreatedAt', 'LastLogin'],
  [T.LOG]: ['Timestamp', 'User', 'Action', 'Entity', 'EntityID', 'Details']
};
// Role -> permissions. "Cabinets" on each user adds a relationship scope (which cabinets they may touch).
const ROLES = {
  Admin: ['read', 'create', 'update', 'delete', 'users'],
  Editor: ['read', 'create', 'update'],
  Viewer: ['read']
};
const DOC_TYPES = ['Land Title', 'Title Transfer', 'Deed of Donation', 'Deed of Sale', 'Property Acknowledgment Receipt',
  'Barangay Property Return Slip', 'Map / Plan', 'Expropriation', 'Resettlement', 'Insurance Policy',
  'Memorandum of Agreement', 'Presidential Proclamation', 'Declaration of Real Property', 'Tax Declaration',
  'Invoice / Receipt of Property', 'Property Transfer Report', 'Other'];
const COPY_TYPES = ['Original', 'Photocopy', 'Duplicate', 'Carbon Copy', 'Draft'];

/* ───────────── Entry points (thin) ───────────── */
function doGet() { return json_({ok: true, data: 'GSO Filing System API is online.'}); }

function doPost(e) {
  let res;
  try {
    res = {ok: true, data: route_(JSON.parse(e.postData.contents))};
  } catch (err) {
    res = {ok: false, code: err.code || 'ERROR', error: err.code ? err.message : 'Server error: ' + err.message};
  }
  return json_(res);
}

function route_(req) {
  const d = req.data || {};
  if (req.action === 'login') return login_(d);
  const u = auth_(req.token);
  switch (req.action) {
    case 'init': return init_(u);
    case 'record.save': return recordSave_(u, d);
    case 'record.delete': return recordDelete_(u, d);
    case 'user.list': need_(u, 'users'); return table_(T.USR).rows.map(userPub_);
    case 'user.save': return userSave_(u, d);
    case 'logout':
      CacheService.getScriptCache().remove('s:' + req.token);
      audit_(u.Username, 'LOGOUT', 'User', u.Username, '');
      return true;
    default: throw err_('BAD_REQUEST', 'Unknown action.');
  }
}

/* ───────────── Auth & access control ───────────── */
function login_(d) {
  const name = clean_(d.username, 40).toLowerCase(), pw = String(d.password || '');
  const cache = CacheService.getScriptCache(), fk = 'f:' + name, fails = Number(cache.get(fk) || 0);
  if (fails >= CFG.MAX_FAILS) throw err_('LOCKED', 'Too many failed attempts. Try again in 15 minutes.');
  const t = table_(T.USR);
  const u = t.rows.find(x => x.Username.toLowerCase() === name);
  if (!u || u.Status !== 'Active' || hash_(pw, u.Salt) !== u.Hash) {
    cache.put(fk, String(fails + 1), CFG.LOCK_SEC);
    audit_(name || '?', 'LOGIN_FAILED', 'User', name, '');
    throw err_('LOGIN', 'Invalid username or password.');
  }
  cache.remove(fk);
  const token = Utilities.getUuid() + Utilities.getUuid().replace(/-/g, '');
  cache.put('s:' + token, JSON.stringify({u: u.Username}), CFG.SESSION_SEC);
  u.LastLogin = iso_();
  put_(t, u._row, u);
  audit_(u.Username, 'LOGIN', 'User', u.Username, '');
  return {token: token, user: userPub_(u)};
}

function auth_(token) {
  const c = token && CacheService.getScriptCache().get('s:' + token);
  if (!c) throw err_('AUTH', 'Session expired. Please sign in again.');
  const u = table_(T.USR).rows.find(x => x.Username === JSON.parse(c).u);
  if (!u || u.Status !== 'Active') throw err_('AUTH', 'This account is inactive.');
  return u;
}
function can_(u, perm) { return (ROLES[u.Role] || []).indexOf(perm) > -1; }
function need_(u, perm) { if (!can_(u, perm)) throw err_('FORBIDDEN', 'Your role (' + u.Role + ') is not allowed to ' + perm + '.'); }
function cabinetOk_(u, cab) {
  const s = (u.Cabinets || '').trim();
  return s === '*' || s.split(',').map(x => x.trim().toLowerCase()).indexOf(String(cab).toLowerCase()) > -1;
}
function userPub_(u) {
  return {username: u.Username, fullName: u.FullName, role: u.Role, cabinets: u.Cabinets, status: u.Status, lastLogin: u.LastLogin};
}
function hash_(pw, salt) {
  let h = salt + pw;
  for (let i = 0; i < CFG.ROUNDS; i++) {
    h = Utilities.base64Encode(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, h + salt, Utilities.Charset.UTF_8));
  }
  return h;
}

/* ───────────── Records (service layer) ───────────── */
function init_(u) {
  const records = table_(T.REC).rows.filter(r => r.Status !== 'Deleted' && cabinetOk_(u, r.Cabinet)).map(recPub_);
  return {user: userPub_(u), perms: ROLES[u.Role] || [], records: records, docTypes: DOC_TYPES, copyTypes: COPY_TYPES, roles: Object.keys(ROLES)};
}

function recordSave_(u, d) {
  const isNew = !d.ID;
  need_(u, isNew ? 'create' : 'update');
  const r = cleanRecord_(d);
  if (!cabinetOk_(u, r.Cabinet)) throw err_('FORBIDDEN', 'You do not have access to cabinet ' + r.Cabinet + '.');
  return locked_(() => {
    const t = table_(T.REC), now = iso_();
    if (isNew) {
      const key = x => [x.Cabinet, x.Drawer, x.FolderNo, x.FileNo, x.Description].join('|').toLowerCase();
      if (r.FileNo && t.rows.some(x => x.Status !== 'Deleted' && key(x) === key(r))) {
        throw err_('DUPLICATE', 'This exact record already exists at that location.');
      }
      const rec = Object.assign({ID: nextId_(t.rows), Status: 'Active', CreatedAt: now, CreatedBy: u.Username,
        UpdatedAt: now, UpdatedBy: u.Username, Version: '1'}, r);
      put_(t, t.sh.getLastRow() + 1, rec);
      audit_(u.Username, 'CREATE', 'Record', rec.ID, r.Cabinet + '/D' + r.Drawer + '/F' + r.FolderNo + '/#' + r.FileNo);
      return recPub_(rec);
    }
    const cur = t.rows.find(x => x.ID === d.ID && x.Status !== 'Deleted');
    if (!cur) throw err_('NOT_FOUND', 'Record no longer exists.');
    if (!cabinetOk_(u, cur.Cabinet)) throw err_('FORBIDDEN', 'You do not have access to cabinet ' + cur.Cabinet + '.');
    if (String(d.Version) !== cur.Version) throw err_('CONFLICT', 'Someone else changed this record. Refresh and try again.');
    const changes = Object.keys(r).filter(k => r[k] !== cur[k]).map(k => k + ': "' + cur[k] + '" -> "' + r[k] + '"');
    Object.assign(cur, r, {UpdatedAt: now, UpdatedBy: u.Username, Version: String(Number(cur.Version) + 1)});
    put_(t, cur._row, cur);
    audit_(u.Username, 'UPDATE', 'Record', cur.ID, changes.join('; ').slice(0, 1500));
    return recPub_(cur);
  });
}

// Soft delete: the row stays in the sheet with Status = Deleted so it can be restored.
function recordDelete_(u, d) {
  need_(u, 'delete');
  return locked_(() => {
    const t = table_(T.REC), cur = t.rows.find(x => x.ID === d.ID && x.Status !== 'Deleted');
    if (!cur) throw err_('NOT_FOUND', 'Record no longer exists.');
    if (!cabinetOk_(u, cur.Cabinet)) throw err_('FORBIDDEN', 'You do not have access to cabinet ' + cur.Cabinet + '.');
    if (String(d.Version) !== cur.Version) throw err_('CONFLICT', 'Someone else changed this record. Refresh and try again.');
    Object.assign(cur, {Status: 'Deleted', UpdatedAt: iso_(), UpdatedBy: u.Username, Version: String(Number(cur.Version) + 1)});
    put_(t, cur._row, cur);
    audit_(u.Username, 'DELETE', 'Record', cur.ID, cur.Cabinet + ' / ' + (cur.FolderName || cur.Description).slice(0, 120));
    return {ID: cur.ID};
  });
}

function cleanRecord_(d) {
  const r = {
    Cabinet: clean_(d.Cabinet, 40), Drawer: clean_(d.Drawer, 20), FolderNo: clean_(d.FolderNo, 20),
    FolderName: clean_(d.FolderName, 400), FileNo: clean_(d.FileNo, 20), Description: clean_(d.Description, 2000, true),
    DocType: clean_(d.DocType, 60) || 'Other', CopyType: clean_(d.CopyType, 30), Remarks: clean_(d.Remarks, 1000, true)
  };
  if (!r.Cabinet || !r.Drawer) throw err_('VALIDATION', 'Cabinet # and Drawer # are required.');
  if (!r.FolderName && !r.Description) throw err_('VALIDATION', 'Enter a Folder Name or a File Description.');
  if (DOC_TYPES.indexOf(r.DocType) < 0) throw err_('VALIDATION', 'Invalid document type.');
  if (r.CopyType && COPY_TYPES.indexOf(r.CopyType) < 0) throw err_('VALIDATION', 'Invalid copy type.');
  return r;
}
function recPub_(r) { const o = {}; COLS[T.REC].forEach(c => o[c] = r[c]); return o; }
function nextId_(rows) {
  const max = rows.reduce((m, r) => Math.max(m, Number(String(r.ID).replace(/\D/g, '')) || 0), 0);
  return 'GSO-' + ('0000' + (max + 1)).slice(-4);
}

/* ───────────── User management (admin only) ───────────── */
function userSave_(u, d) {
  need_(u, 'users');
  const name = clean_(d.username, 40), role = d.role, status = d.status === 'Inactive' ? 'Inactive' : 'Active', pw = String(d.password || '');
  if (!/^[A-Za-z0-9._-]{3,40}$/.test(name)) throw err_('VALIDATION', 'Username: 3-40 letters, numbers, dot, dash or underscore.');
  if (!ROLES[role]) throw err_('VALIDATION', 'Invalid role.');
  if (pw && !/^(?=.*[A-Za-z])(?=.*\d).{8,}$/.test(pw)) throw err_('VALIDATION', 'Password needs 8+ characters with letters and numbers.');
  return locked_(() => {
    const t = table_(T.USR), cur = t.rows.find(x => x.Username.toLowerCase() === name.toLowerCase());
    if (!cur && !pw) throw err_('VALIDATION', 'A password is required for new users.');
    if (cur && cur.Username === u.Username && (role !== 'Admin' || status !== 'Active')) {
      throw err_('VALIDATION', 'You cannot demote or deactivate your own account.');
    }
    const o = cur || {Username: name, CreatedAt: iso_(), LastLogin: ''};
    o.FullName = clean_(d.fullName, 80) || name;
    o.Role = role;
    o.Cabinets = clean_(d.cabinets, 200) || '*';
    o.Status = status;
    if (pw) { o.Salt = Utilities.getUuid(); o.Hash = hash_(pw, o.Salt); }
    put_(t, cur ? cur._row : t.sh.getLastRow() + 1, o);
    audit_(u.Username, cur ? 'USER_UPDATE' : 'USER_CREATE', 'User', o.Username,
      role + ' | cabinets: ' + o.Cabinets + ' | ' + status + (pw ? ' | password set' : ''));
    return userPub_(o);
  });
}

/* ───────────── Data-access helpers ───────────── */
function ss_() { return CFG.SS_ID ? SpreadsheetApp.openById(CFG.SS_ID) : SpreadsheetApp.getActiveSpreadsheet(); }
function table_(name) {
  const sh = ss_().getSheetByName(name);
  if (!sh) throw err_('SETUP', 'Missing sheet "' + name + '". Run setup() first.');
  const cols = COLS[name], n = Math.max(sh.getLastRow() - 1, 0);
  const vals = n ? sh.getRange(2, 1, n, cols.length).getValues() : [];
  const rows = vals.map((v, i) => { const o = {_row: i + 2}; cols.forEach((c, j) => o[c] = String(v[j])); return o; });
  return {sh: sh, cols: cols, rows: rows};
}
function put_(t, row, obj) {
  t.sh.getRange(row, 1, 1, t.cols.length).setValues([t.cols.map(c => obj[c] == null ? '' : String(obj[c]))]);
}
function audit_(user, action, entity, id, details) {
  ss_().getSheetByName(T.LOG).appendRow([iso_(), user, action, entity, id, details]);
}
function locked_(fn) {
  const l = LockService.getScriptLock();
  l.waitLock(20000);
  try { return fn(); } finally { l.releaseLock(); }
}
function json_(o) { return ContentService.createTextOutput(JSON.stringify(o)).setMimeType(ContentService.MimeType.JSON); }
function err_(code, msg) { const e = new Error(msg); e.code = code; return e; }
function iso_() { return Utilities.formatDate(new Date(), Session.getScriptTimeZone(), "yyyy-MM-dd'T'HH:mm:ss"); }
function clean_(v, max, multiline) {
  const s = String(v == null ? '' : v).replace(/[\u0000-\u0008\u000B-\u001F]/g, ' ')
    .replace(multiline ? /[^\S\n]+/g : /\s+/g, ' ').replace(/ ?\n ?/g, multiline ? '\n' : ' ').trim();
  return max ? s.slice(0, max) : s;
}

/* ───────────── One-time setup ───────────── */
function setup() {
  const ss = ss_();
  [T.REC, T.USR, T.LOG].forEach(name => {
    const cols = COLS[name], sh = ss.getSheetByName(name) || ss.insertSheet(name);
    sh.getRange(1, 1, sh.getMaxRows(), cols.length).setNumberFormat('@'); // keep everything as text (no auto date/number/formula conversion)
    sh.getRange(1, 1, 1, cols.length).setValues([cols]).setFontWeight('bold').setBackground('#1f3a5f').setFontColor('#ffffff');
    sh.setFrozenRows(1);
  });
  const t = table_(T.USR);
  if (t.rows.length) { Logger.log('Users already exist. Setup refreshed headers only.'); return; }
  const pw = 'Gso-' + Utilities.getUuid().slice(0, 8) + '7', salt = Utilities.getUuid();
  put_(t, 2, {Username: 'admin', FullName: 'System Administrator', Role: 'Admin', Cabinets: '*', Status: 'Active',
    Salt: salt, Hash: hash_(pw, salt), CreatedAt: iso_(), LastLogin: ''});
  Logger.log('FIRST ADMIN  ->  username: admin   password: ' + pw + '   (change it right after your first login)');
}

/* Sets (or re-creates) the "admin" account with a known TEMPORARY password and clears any login lockout.
   Run it from the editor, sign in, then change the password under Users & roles. */
function resetAdminPassword() {
  const pw = 'Admin123456', salt = Utilities.getUuid(), t = table_(T.USR);
  const u = t.rows.find(x => x.Username.toLowerCase() === 'admin') ||
    {Username: 'admin', FullName: 'System Administrator', Cabinets: '*', CreatedAt: iso_(), LastLogin: ''};
  Object.assign(u, {Role: 'Admin', Status: 'Active', Salt: salt, Hash: hash_(pw, salt)});
  put_(t, u._row || t.sh.getLastRow() + 1, u);
  CacheService.getScriptCache().remove('f:admin');
  Logger.log('admin password is now the temporary value set in resetAdminPassword(). Change it after logging in.');
}

/* ───────────── Legacy import (GSOFILINGRECORDS.xlsx -> Records) ───────────── */
function importLegacy(force) {
  const src = findCatalog_();
  const t = table_(T.REC);
  if (t.rows.length && !force) throw new Error('Records already has data. Run importLegacy(true) only if you want to append again.');
  const n = src.sh.getLastRow() - src.row;
  if (n < 1) throw new Error('Tab "' + src.sh.getName() + '" has a header but no data rows below it.');
  const raw = src.sh.getRange(src.row + 1, src.col, n, 7).getValues();
  const recs = legacyToRecords_(raw, iso_(), t.rows.length);
  if (!recs.length) throw new Error('Tab "' + src.sh.getName() + '" has no data rows to import.');
  const out = recs.map(r => COLS[T.REC].map(c => r[c]));
  t.sh.getRange(t.sh.getLastRow() + 1, 1, out.length, COLS[T.REC].length).setValues(out);
  audit_('system', 'IMPORT', 'Record', '', out.length + ' rows from tab ' + src.sh.getName());
  Logger.log('Imported ' + out.length + ' records from "' + src.sh.getName() + '". Review the DocType column - it was auto-detected from folder names.');
}

// Looks for the "CABINET #" header in the first rows/columns of every tab, wherever the title row or offset puts it.
function findCatalog_() {
  const sheets = ss_().getSheets(), seen = [];
  for (const sh of sheets) {
    const rows = Math.min(sh.getLastRow(), 8), cols = Math.min(sh.getLastColumn(), 6);
    if (rows < 1 || cols < 1) { seen.push(sh.getName() + ' (empty)'); continue; }
    const v = sh.getRange(1, 1, rows, cols).getValues();
    for (let r = 0; r < rows; r++) for (let c = 0; c < cols; c++) {
      if (/^cabinet\s*#?$/i.test(String(v[r][c]).trim())) return {sh: sh, row: r + 1, col: c + 1};
    }
    seen.push(sh.getName() + ' (' + sh.getLastRow() + ' rows; A1="' + String(v[0][0]).slice(0, 25) + '")');
  }
  throw new Error('Could not find the catalog header "CABINET #". Tabs seen: ' + seen.join(' | ') +
    '. Import GSOFILINGRECORDS.xlsx into THIS spreadsheet (File > Import > Insert new sheet).');
}

function legacyToRecords_(raw, now, startSeq) {
  let seq = startSeq || 0;
  const out = [];
  raw.forEach(r => {
    if (r.every(v => String(v).trim() === '')) return;
    const cab = clean_(r[0]), fname = fixTypos_(clean_(r[3], 400)), rem = clean_(r[6], 1000, true), copy = copyType_(rem);
    out.push({
      ID: 'GSO-' + ('0000' + (++seq)).slice(-4), Cabinet: cab, Drawer: clean_(r[1]), FolderNo: clean_(r[2]),
      FolderName: fname, FileNo: clean_(r[4]), Description: fixTypos_(clean_(r[5], 2000, true)),
      DocType: guessType_(cab, fname), CopyType: copy, Remarks: copy && rem.length <= 12 ? '' : rem,
      Status: 'Active', CreatedAt: now, CreatedBy: 'import', UpdatedAt: now, UpdatedBy: 'import', Version: '1'
    });
  });
  return out;
}
function fixTypos_(s) { return s.replace(/Retrun/g, 'Return').replace(/Resettlemet\b/g, 'Resettlement'); }
function copyType_(rem) {
  const m = [[/original/i, 'Original'], [/photocopy/i, 'Photocopy'], [/carbon/i, 'Carbon Copy'], [/duplicate/i, 'Duplicate'], [/draft/i, 'Draft']];
  const hit = m.find(x => x[0].test(rem));
  return hit ? hit[1] : '';
}
function guessType_(cab, fname) {
  if (/^maps/i.test(cab)) return 'Map / Plan';
  const rules = [
    [/property transfer report|\bPTR\b/i, 'Property Transfer Report'], [/invoice/i, 'Invoice / Receipt of Property'],
    [/return slip|\bPRS\b/i, 'Barangay Property Return Slip'], [/acknowledg|PAR\/ARE/i, 'Property Acknowledgment Receipt'],
    [/deed of sale/i, 'Deed of Sale'], [/donation/i, 'Deed of Donation'], [/titles for transfer|titling/i, 'Title Transfer'],
    [/\btitles?\b|affidavit of loss/i, 'Land Title'], [/expropriat/i, 'Expropriation'], [/resettlement/i, 'Resettlement'],
    [/insurance|GSIS/i, 'Insurance Policy'], [/memorandum of agreement|\bMOA\b/i, 'Memorandum of Agreement'],
    [/proclamation/i, 'Presidential Proclamation'], [/declaration of real property/i, 'Declaration of Real Property'],
    [/tax declaration/i, 'Tax Declaration'], [/\bmap\b|\bplan\b/i, 'Map / Plan']
  ];
  const hit = rules.find(x => x[0].test(fname));
  return hit ? hit[1] : 'Other';
}
