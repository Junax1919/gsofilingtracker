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
  ROUNDS: 500,             // password hash iterations
  DRIVE_FOLDER: '1usqmzEAG-LSiFzTRusMkYskEopoexgev', // Google Drive folder for PDF attachments and profile photos
  MAX_PDF: 8 * 1024 * 1024 // largest PDF accepted (bytes)
};
const SH_ = {}; let SS_ = null; // per-execution memo of the spreadsheet and sheet handles
const T = {REC: 'Records', USR: 'Users', LOG: 'AuditLog', SET: 'Settings', PHO: 'Photos'};
const COLS = {
  [T.REC]: ['ID', 'Cabinet', 'Drawer', 'FolderNo', 'FolderName', 'FileNo', 'Description', 'DocType', 'CopyType', 'Remarks',
            'Status', 'CreatedAt', 'CreatedBy', 'UpdatedAt', 'UpdatedBy', 'Version', 'FileId', 'FileName'],
  [T.USR]: ['Username', 'FullName', 'Role', 'Cabinets', 'Status', 'Salt', 'Hash', 'CreatedAt', 'LastLogin', 'Division', 'Email'],
  [T.LOG]: ['Timestamp', 'User', 'Action', 'Entity', 'EntityID', 'Details'],
  [T.SET]: ['Key', 'Value'],
  [T.PHO]: ['Username', 'Photo', 'UpdatedAt', 'FileId']
};
// Role -> permissions. "Cabinets" on each user adds a relationship scope (which cabinets they may touch).
const ROLES = {
  Admin: ['read', 'create', 'update', 'delete', 'attach', 'options', 'users', 'audit', 'settings'],
  Editor: ['read', 'create', 'update', 'delete', 'attach', 'options', 'audit'],
  Viewer: ['read']
};
const DOC_TYPES = ['Land Title', 'Title Transfer', 'Deed of Donation', 'Deed of Sale', 'Property Acknowledgment Receipt',
  'Barangay Property Return Slip', 'Map / Plan', 'Expropriation', 'Resettlement', 'Insurance Policy',
  'Memorandum of Agreement', 'Presidential Proclamation', 'Declaration of Real Property', 'Tax Declaration',
  'Invoice / Receipt of Property', 'Property Transfer Report', 'Other'];
const COPY_TYPES = ['Original', 'Photocopy', 'Duplicate', 'Carbon Copy', 'Draft'];
const DIVISIONS = ['Admin Division', 'Supply Division', 'Records Division'];
const THEMES = ['blue', 'green', 'purple', 'teal', 'crimson', 'slate'];
const DEFAULT_SETTINGS = {systemName: 'GSO Filing System', orgName: 'General Services Office', theme: 'blue', pageSize: '10',
  sessionHours: '6', customDocTypes: '[]', customCopyTypes: '[]'};

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
  if (req.action === 'public') return publicSettings_();
  const u = auth_(req.token);
  switch (req.action) {
    case 'init': return init_(u, d.fresh === true);
    case 'record.save': return recordSave_(u, d);
    case 'record.delete': return recordDelete_(u, d);
    case 'audit.list': return auditList_(u);
    case 'audit.view':
      if (/^GSO-\d+$/.test(String(d.ID))) audit_(u.Username, 'VIEW', 'Record', d.ID, '');
      return true;
    case 'option.add': return optionAdd_(u, d);
    case 'settings.save': return settingsSave_(u, d);
    case 'file.get': return fileGet_(u, d);
    case 'file.upload': return fileUpload_(u, d);
    case 'file.remove': return fileRemove_(u, d);
    case 'profile.save': return profileSave_(u, d);
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
  const u = usersCached_().find(x => x.Username.toLowerCase() === name);
  if (!u || u.Status !== 'Active' || hash_(pw, u.Salt) !== u.Hash) {
    cache.put(fk, String(fails + 1), CFG.LOCK_SEC);
    audit_(name || '?', 'LOGIN_FAILED', 'User', name, '');
    throw err_('LOGIN', 'Invalid username or password.');
  }
  cache.remove(fk);
  const token = Utilities.getUuid() + Utilities.getUuid().replace(/-/g, '');
  cache.put('s:' + token, JSON.stringify({u: u.Username}), Number(getSettings_().sessionHours || 6) * 3600);
  u.LastLogin = iso_();
  sheet_(T.USR).getRange(u._row, COLS[T.USR].indexOf('LastLogin') + 1).setValue(u.LastLogin);
  audit_(u.Username, 'LOGIN', 'User', u.Username, '');
  return {token: token, user: userPub_(u), init: init_(u)}; // one round trip: sign-in + all data
}

function auth_(token) {
  const c = token && CacheService.getScriptCache().get('s:' + token);
  if (!c) throw err_('AUTH', 'Session expired. Please sign in again.');
  const u = usersCached_().find(x => x.Username === JSON.parse(c).u);
  if (!u || u.Status !== 'Active') throw err_('AUTH', 'This account is inactive.');
  return u;
}
function perms_(u) {
  const p = (ROLES[u.Role] || []).slice();
  return p;
}
function can_(u, perm) { return perms_(u).indexOf(perm) > -1; }
function need_(u, perm) { if (!can_(u, perm)) throw err_('FORBIDDEN', 'Your role (' + u.Role + ') is not allowed to ' + perm + '.'); }
function cabinetOk_(u, cab) {
  const s = (u.Cabinets || '').trim();
  return s === '*' || s.split(',').map(x => x.trim().toLowerCase()).indexOf(String(cab).toLowerCase()) > -1;
}
function userPub_(u) {
  return {username: u.Username, fullName: u.FullName, role: u.Role, cabinets: u.Cabinets, status: u.Status, lastLogin: u.LastLogin, division: u.Division || '', email: u.Email || ''};
}
function hash_(pw, salt) {
  let h = salt + pw;
  for (let i = 0; i < CFG.ROUNDS; i++) {
    h = Utilities.base64Encode(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, h + salt, Utilities.Charset.UTF_8));
  }
  return h;
}

/* ───────────── Records (service layer) ───────────── */
function init_(u, fresh) {
  const records = activeRecords_(fresh).filter(r => cabinetOk_(u, r.Cabinet));
  return {user: Object.assign(userPub_(u), {photo: getPhoto_(u.Username)}), perms: perms_(u), records: records, docTypes: docTypes_(), copyTypes: copyTypes_(), roles: Object.keys(ROLES),
    divisions: DIVISIONS, settings: getSettings_()};
}

function recordSave_(u, d) {
  const isNew = !d.ID;
  need_(u, isNew ? 'create' : 'update');
  const r = cleanRecord_(d);
  if (!cabinetOk_(u, r.Cabinet)) throw err_('FORBIDDEN', 'You do not have access to cabinet ' + r.Cabinet + '.');
  return locked_(() => {
    const sh = sheet_(T.REC), t = {sh: sh, cols: COLS[T.REC]}, now = iso_();
    if (isNew) {
      const key = x => [x.Cabinet, x.Drawer, x.FolderNo, x.FileNo, x.Description].join('|').toLowerCase();
      if (r.FileNo && activeRecords_().some(x => key(x) === key(r))) throw err_('DUPLICATE', 'This exact record already exists at that location.');
      const rec = Object.assign({ID: nextId_(sh), Status: 'Active', CreatedAt: now, CreatedBy: u.Username,
        UpdatedAt: now, UpdatedBy: u.Username, Version: '1', FileId: '', FileName: ''}, r);
      put_(t, sh.getLastRow() + 1, rec);
      dropRecCache_();
      audit_(u.Username, 'CREATE', 'Record', rec.ID, r.Cabinet + '/D' + r.Drawer + '/F' + r.FolderNo + '/#' + r.FileNo);
      return recPub_(rec);
    }
    const cur = loadRec_(sh, d.ID, u);
    if (String(d.Version) !== cur.Version) throw err_('CONFLICT', 'Someone else changed this record. Refresh and try again.');
    const changes = Object.keys(r).filter(k => r[k] !== cur[k]).map(k => k + ': "' + cur[k] + '" -> "' + r[k] + '"');
    Object.assign(cur, r, {UpdatedAt: now, UpdatedBy: u.Username, Version: String(Number(cur.Version) + 1)});
    put_(t, cur._row, cur);
    dropRecCache_();
    audit_(u.Username, 'UPDATE', 'Record', cur.ID, changes.join('; ').slice(0, 1500));
    return recPub_(cur);
  });
}

// Soft delete: the row stays in the sheet with Status = Deleted so it can be restored.
function recordDelete_(u, d) {
  need_(u, 'delete');
  return locked_(() => {
    const sh = sheet_(T.REC), cur = loadRec_(sh, d.ID, u);
    if (String(d.Version) !== cur.Version) throw err_('CONFLICT', 'Someone else changed this record. Refresh and try again.');
    Object.assign(cur, {Status: 'Deleted', UpdatedAt: iso_(), UpdatedBy: u.Username, Version: String(Number(cur.Version) + 1)});
    put_({sh: sh, cols: COLS[T.REC]}, cur._row, cur);
    dropRecCache_();
    audit_(u.Username, 'DELETE', 'Record', cur.ID, cur.Cabinet + ' / ' + (cur.FolderName || cur.Description).slice(0, 120));
    return {ID: cur.ID};
  });
}

/* Fast paths: find one record by reading only column A, then read/write just that row (no full-sheet scans). */
function recRow_(sh, id) {
  const last = sh.getLastRow();
  if (last < 2) return 0;
  const i = sh.getRange(2, 1, last - 1, 1).getValues().findIndex(r => String(r[0]) === String(id));
  return i < 0 ? 0 : i + 2;
}
function loadRec_(sh, id, u) {
  const row = recRow_(sh, id);
  if (!row) throw err_('NOT_FOUND', 'Record no longer exists.');
  const v = sh.getRange(row, 1, 1, COLS[T.REC].length).getValues()[0], o = {_row: row};
  COLS[T.REC].forEach((c, j) => o[c] = String(v[j]));
  if (o.Status === 'Deleted') throw err_('NOT_FOUND', 'Record no longer exists.');
  if (!cabinetOk_(u, o.Cabinet)) throw err_('FORBIDDEN', 'You do not have access to cabinet ' + o.Cabinet + '.');
  return o;
}

function cleanRecord_(d) {
  const r = {
    Cabinet: clean_(d.Cabinet, 40), Drawer: clean_(d.Drawer, 20), FolderNo: clean_(d.FolderNo, 20),
    FolderName: clean_(d.FolderName, 400), FileNo: clean_(d.FileNo, 20), Description: clean_(d.Description, 2000, true),
    DocType: clean_(d.DocType, 60) || 'Other', CopyType: clean_(d.CopyType, 30), Remarks: clean_(d.Remarks, 1000, true)
  };
  if (!r.Cabinet || !r.Drawer) throw err_('VALIDATION', 'Cabinet # and Drawer # are required.');
  if (!r.FolderName && !r.Description) throw err_('VALIDATION', 'Enter a Folder Name or a File Description.');
  if (docTypes_().indexOf(r.DocType) < 0) throw err_('VALIDATION', 'Invalid document type.');
  if (r.CopyType && copyTypes_().indexOf(r.CopyType) < 0) throw err_('VALIDATION', 'Invalid copy type.');
  return r;
}
function recPub_(r) { // Drive file IDs never leave the server
  const o = {};
  COLS[T.REC].forEach(c => { if (c !== 'FileId') o[c] = r[c]; });
  o.HasFile = r.FileId ? '1' : '';
  return o;
}
function nextId_(sh) {
  const last = sh.getLastRow();
  const max = last < 2 ? 0 : sh.getRange(2, 1, last - 1, 1).getValues().reduce((m, r) => Math.max(m, Number(String(r[0]).replace(/\D/g, '')) || 0), 0);
  return 'GSO-' + ('0000' + (max + 1)).slice(-4);
}

/* ───────────── PDF attachments (stored in the Google Drive folder; served only through this login) ───────────── */
function driveFolder_() {
  try { return DriveApp.getFolderById(CFG.DRIVE_FOLDER); }
  catch (e) { throw err_('DRIVE', 'Cannot open the Google Drive folder. Make sure the account that owns this script can edit it. (' + e.message + ')'); }
}
function fileUpload_(u, d) {
  need_(u, 'attach');
  const base = clean_(d.name, 120).replace(/\.pdf$/i, '').replace(/[\\/:*?"<>|]+/g, '_').trim() || 'document';
  let bytes;
  try { bytes = Utilities.base64Decode(String(d.data || '')); } catch (e) { throw err_('VALIDATION', 'The file could not be read.'); }
  if (!bytes.length || bytes.length > CFG.MAX_PDF) throw err_('VALIDATION', 'The PDF must be smaller than 8 MB.');
  if (bytes[0] !== 0x25 || bytes[1] !== 0x50 || bytes[2] !== 0x44 || bytes[3] !== 0x46) throw err_('VALIDATION', 'That file is not a valid PDF.');
  const sh = sheet_(T.REC);
  loadRec_(sh, d.ID, u); // existence + cabinet access, before spending time on Drive
  const file = driveFolder_().createFile(Utilities.newBlob(bytes, 'application/pdf', d.ID + ' - ' + base + '.pdf'));
  return locked_(() => {
    let cur;
    try { cur = loadRec_(sh, d.ID, u); } catch (e) { file.setTrashed(true); throw e; }
    const oldId = cur.FileId;
    Object.assign(cur, {FileId: file.getId(), FileName: base + '.pdf', UpdatedAt: iso_(), UpdatedBy: u.Username, Version: String(Number(cur.Version) + 1)});
    put_({sh: sh, cols: COLS[T.REC]}, cur._row, cur);
    dropRecCache_();
    audit_(u.Username, 'FILE_ATTACH', 'Record', cur.ID, cur.FileName + ' (' + Math.round(bytes.length / 1024) + ' KB)');
    if (oldId) { try { DriveApp.getFileById(oldId).setTrashed(true); } catch (e) {} } // replaced file goes to the Drive trash
    return recPub_(cur);
  });
}
function fileRemove_(u, d) {
  need_(u, 'attach');
  return locked_(() => {
    const sh = sheet_(T.REC), cur = loadRec_(sh, d.ID, u);
    if (!cur.FileId) return recPub_(cur);
    const oldId = cur.FileId, name = cur.FileName;
    Object.assign(cur, {FileId: '', FileName: '', UpdatedAt: iso_(), UpdatedBy: u.Username, Version: String(Number(cur.Version) + 1)});
    put_({sh: sh, cols: COLS[T.REC]}, cur._row, cur);
    dropRecCache_();
    audit_(u.Username, 'FILE_REMOVE', 'Record', cur.ID, name);
    try { DriveApp.getFileById(oldId).setTrashed(true); } catch (e) {}
    return recPub_(cur);
  });
}
function fileGet_(u, d) {
  need_(u, 'read');
  const cur = loadRec_(sheet_(T.REC), d.ID, u);
  if (!cur.FileId) throw err_('NOT_FOUND', 'This record has no attachment.');
  let bytes;
  try { bytes = DriveApp.getFileById(cur.FileId).getBlob().getBytes(); } catch (e) { throw err_('DRIVE', 'The attached file could not be opened from Google Drive.'); }
  audit_(u.Username, 'FILE_VIEW', 'Record', cur.ID, cur.FileName);
  return {name: cur.FileName, data: Utilities.base64Encode(bytes)};
}
// Run once from the editor to grant Drive access, then redeploy a New version of the Web App.
function authorizeDrive() { Logger.log('Drive OK. Files will be saved in folder: "' + driveFolder_().getName() + '"'); }

/* ───────────── User management (admin only) ───────────── */
function userSave_(u, d) {
  need_(u, 'users');
  const name = clean_(d.username, 40), role = d.role, status = d.status === 'Inactive' ? 'Inactive' : 'Active', pw = String(d.password || '');
  if (!/^[A-Za-z0-9._-]{3,40}$/.test(name)) throw err_('VALIDATION', 'Username: 3-40 letters, numbers, dot, dash or underscore.');
  if (!ROLES[role]) throw err_('VALIDATION', 'Invalid role.');
  const email = clean_(d.email, 120).toLowerCase();
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) throw err_('VALIDATION', 'Enter a valid email address.');
  const division = clean_(d.division, 40);
  if (division && DIVISIONS.indexOf(division) < 0) throw err_('VALIDATION', 'Invalid division.');
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
    if (email && t.rows.some(x => x.Email.toLowerCase() === email && x.Username !== o.Username)) throw err_('DUPLICATE', 'That email is already used by another user.');
    o.Email = email;
    o.Division = division; // only reachable by Admins (need_ 'users')
    if (pw) { o.Salt = Utilities.getUuid(); o.Hash = hash_(pw, o.Salt); }
    put_(t, cur ? cur._row : t.sh.getLastRow() + 1, o);
    CacheService.getScriptCache().remove('users');
    audit_(u.Username, cur ? 'USER_UPDATE' : 'USER_CREATE', 'User', o.Username,
      role + ' | ' + (division || 'no division') + ' | ' + (email || 'no email') + ' | cabinets: ' + o.Cabinets + ' | ' + status + (pw ? ' | password set' : ''));
    return userPub_(o);
  });
}

/* ───────────── Speed: server-side caches (rebuilt automatically after any change) ───────────── */
function usersCached_() {
  const c = CacheService.getScriptCache(), s = c.get('users');
  if (s) return JSON.parse(s);
  const rows = table_(T.USR).rows;
  c.put('users', JSON.stringify(rows), 600);
  return rows;
}
function activeRecords_(fresh) {
  if (!fresh) { const s = cacheGetBig_('rec'); if (s) return JSON.parse(s); }
  const list = table_(T.REC).rows.filter(r => r.Status !== 'Deleted').map(recPub_);
  cachePutBig_('rec', JSON.stringify(list));
  return list;
}
function dropRecCache_() { CacheService.getScriptCache().remove('rec:n'); }
function cachePutBig_(key, str) { // CacheService caps each value at 100 KB, so large lists are stored in chunks
  const size = 30000, n = Math.max(Math.ceil(str.length / size), 1), o = {};
  for (let i = 0; i < n; i++) o[key + ':' + i] = str.slice(i * size, (i + 1) * size);
  o[key + ':n'] = String(n);
  CacheService.getScriptCache().putAll(o, 600);
}
function cacheGetBig_(key) {
  const c = CacheService.getScriptCache(), n = Number(c.get(key + ':n'));
  if (!n) return null;
  const keys = []; for (let i = 0; i < n; i++) keys.push(key + ':' + i);
  const m = c.getAll(keys); let out = '';
  for (let i = 0; i < n; i++) { if (m[key + ':' + i] == null) return null; out += m[key + ':' + i]; }
  return out;
}
// Optional: run installKeepWarm() once. A 5-minute trigger keeps the script and caches warm so the first load is instant.
function keepWarm() { getSettings_(); usersCached_(); activeRecords_(false); }
function installKeepWarm() {
  ScriptApp.getProjectTriggers().filter(t => t.getHandlerFunction() === 'keepWarm').forEach(t => ScriptApp.deleteTrigger(t));
  ScriptApp.newTrigger('keepWarm').timeBased().everyMinutes(5).create();
  Logger.log('Keep-warm trigger installed (every 5 minutes).');
}

/* ───────────── My profile (every signed-in user, own account only) ───────────── */
function profileSave_(u, d) {
  const name = clean_(d.fullName, 80), email = clean_(d.email, 120).toLowerCase(), np = String(d.newPassword || ''), cache = CacheService.getScriptCache(), fk = 'pf:' + u.Username;
  if (name.length < 2) throw err_('VALIDATION', 'Full name must be at least 2 characters.');
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) throw err_('VALIDATION', 'Enter a valid email address.');
  if (np) {
    if (Number(cache.get(fk) || 0) >= CFG.MAX_FAILS) throw err_('LOCKED', 'Too many wrong current-password attempts. Try again in 15 minutes.');
    if (!/^(?=.*[A-Za-z])(?=.*\d).{8,}$/.test(np)) throw err_('VALIDATION', 'New password needs 8+ characters with letters and numbers.');
    if (hash_(String(d.currentPassword || ''), u.Salt) !== u.Hash) {
      cache.put(fk, String(Number(cache.get(fk) || 0) + 1), CFG.LOCK_SEC);
      throw err_('VALIDATION', 'Current password is incorrect.');
    }
    cache.remove(fk);
  }
  const photo = d.photo === undefined ? null : String(d.photo); // null = keep, '' = remove, data URL = replace
  if (photo && (photo.length > 45000 || !/^data:image\/jpeg;base64,[A-Za-z0-9+\/=]+$/.test(photo))) throw err_('VALIDATION', 'Invalid photo. Please choose a JPG or PNG image.');
  return locked_(() => {
    const t = table_(T.USR), cur = t.rows.find(x => x.Username === u.Username), changed = [];
    if (!cur) throw err_('NOT_FOUND', 'Account not found.');
    if (email && t.rows.some(x => x.Email.toLowerCase() === email && x.Username !== cur.Username)) throw err_('DUPLICATE', 'That email is already used by another user.');
    if (cur.FullName !== name) changed.push('name');
    if (cur.Email !== email) changed.push('email');
    cur.FullName = name; cur.Email = email;
    if (np) { cur.Salt = Utilities.getUuid(); cur.Hash = hash_(np, cur.Salt); changed.push('password'); }
    put_(t, cur._row, cur);
    CacheService.getScriptCache().remove('users');
    let warning = '';
    if (photo !== null) { warning = setPhoto_(cur.Username, photo); changed.push(photo ? 'photo' : 'photo removed'); }
    if (changed.length) audit_(u.Username, 'PROFILE_UPDATE', 'User', cur.Username, 'Changed: ' + changed.join(', '));
    return Object.assign(userPub_(cur), {photo: getPhoto_(cur.Username), warning: warning});
  });
}
// Photos live in their own tab so the Users cache stays small.
function getPhoto_(username) {
  const c = CacheService.getScriptCache(), k = 'photo:' + username, hit = c.get(k);
  if (hit !== null) return hit === '-' ? '' : hit;
  const sh = sheet_(T.PHO), last = sh.getLastRow();
  const i = last > 1 ? sh.getRange(2, 1, last - 1, 1).getValues().map(r => String(r[0])).indexOf(username) : -1;
  const v = i > -1 ? String(sh.getRange(i + 2, 2).getValue()) : '';
  c.put(k, v || '-', 21600);
  return v;
}
function setPhoto_(username, photo) { // fast copy in the Photos tab (instant display) + the file in the Drive folder
  const sh = sheet_(T.PHO), last = sh.getLastRow();
  const i = last > 1 ? sh.getRange(2, 1, last - 1, 1).getValues().map(r => String(r[0])).indexOf(username) : -1;
  const oldId = i > -1 ? String(sh.getRange(i + 2, 4).getValue()) : '';
  let fileId = '', warning = '';
  if (photo) {
    try { fileId = driveFolder_().createFile(Utilities.newBlob(Utilities.base64Decode(photo.split(',')[1]), 'image/jpeg', 'profile-' + username + '.jpg')).getId(); }
    catch (e) { warning = 'Photo saved, but it could not be copied to the Drive folder: ' + e.message; }
  }
  if (oldId && (fileId || !photo)) { try { DriveApp.getFileById(oldId).setTrashed(true); } catch (e) {} }
  if (!photo) { if (i > -1) sh.deleteRow(i + 2); }
  else if (i > -1) sh.getRange(i + 2, 2, 1, 3).setValues([[photo, iso_(), fileId || oldId]]);
  else sh.appendRow([username, photo, iso_(), fileId]);
  CacheService.getScriptCache().remove('photo:' + username);
  return warning;
}

/* ───────────── Settings, options & audit log ───────────── */
function getSettings_() {
  const cache = CacheService.getScriptCache(), c = cache.get('settings');
  if (c) return JSON.parse(c);
  const s = Object.assign({}, DEFAULT_SETTINGS);
  table_(T.SET).rows.forEach(r => { if (r.Key) s[r.Key] = r.Value; });
  cache.put('settings', JSON.stringify(s), 21600);
  return s;
}
function setKV_(t, k, v) {
  const r = t.rows.find(x => x.Key === k);
  if (r) { r.Value = v; put_(t, r._row, r); } else put_(t, t.sh.getLastRow() + 1, {Key: k, Value: v});
}
function publicSettings_() { const s = getSettings_(); return {systemName: s.systemName, orgName: s.orgName, theme: s.theme}; }
function docTypes_() { return DOC_TYPES.concat(JSON.parse(getSettings_().customDocTypes || '[]')); }
function copyTypes_() { return COPY_TYPES.concat(JSON.parse(getSettings_().customCopyTypes || '[]')); }

function settingsSave_(u, d) {
  need_(u, 'settings');
  const n = {
    systemName: clean_(d.systemName, 60), orgName: clean_(d.orgName, 80), theme: String(d.theme),
    pageSize: String(d.pageSize), sessionHours: String(d.sessionHours)
  };
  if (n.systemName.length < 2) throw err_('VALIDATION', 'System name must be at least 2 characters.');
  if (THEMES.indexOf(n.theme) < 0) throw err_('VALIDATION', 'Invalid color theme.');
  if (['10', '30', '50', 'all'].indexOf(n.pageSize) < 0) throw err_('VALIDATION', 'Invalid rows per page.');
  if (['1', '2', '3', '4', '5', '6'].indexOf(n.sessionHours) < 0) throw err_('VALIDATION', 'Session length must be 1-6 hours.');
  return locked_(() => {
    const t = table_(T.SET), old = getSettings_(), changed = [];
    Object.keys(n).forEach(k => { if (old[k] !== n[k]) { changed.push(k + ': "' + old[k] + '" -> "' + n[k] + '"'); setKV_(t, k, n[k]); } });
    CacheService.getScriptCache().remove('settings');
    if (changed.length) audit_(u.Username, 'SETTINGS_UPDATE', 'Settings', '', changed.join('; ').slice(0, 1500));
    return getSettings_();
  });
}

// Admins and Editors may add a Document Type / Copy Type that is not in the list yet.
function optionAdd_(u, d) {
  need_(u, 'options');
  const kind = d.kind === 'copy' ? 'copy' : 'doc', v = clean_(d.value, 60);
  if (!/^[A-Za-z0-9][A-Za-z0-9 \/&().,'-]{1,59}$/.test(v)) throw err_('VALIDATION', 'Use 2-60 letters, numbers or basic punctuation.');
  return locked_(() => {
    const key = kind === 'copy' ? 'customCopyTypes' : 'customDocTypes', hit = (kind === 'copy' ? copyTypes_() : docTypes_()).find(x => x.toLowerCase() === v.toLowerCase());
    if (!hit) {
      const arr = JSON.parse(getSettings_()[key] || '[]');
      arr.push(v);
      setKV_(table_(T.SET), key, JSON.stringify(arr));
      CacheService.getScriptCache().remove('settings');
      audit_(u.Username, 'OPTION_ADD', 'Option', kind === 'copy' ? 'Copy type' : 'Document type', v);
    }
    return {kind: kind, value: hit || v};
  });
}

function auditList_(u) {
  need_(u, 'audit');
  const sh = sheet_(T.LOG), last = sh.getLastRow();
  if (last < 2) return [];
  const from = Math.max(2, last - 999); // newest 1000 entries
  return sh.getRange(from, 1, last - from + 1, 6).getValues().reverse().map(r => ({
    time: String(r[0]).replace('T', ' '), user: String(r[1]), action: String(r[2]), entity: String(r[3]), id: String(r[4]), details: String(r[5])}));
}

function sheet_(name) {
  if (SH_[name]) return SH_[name];
  const ss = ss_(), cols = COLS[name], cache = CacheService.getScriptCache(), k = 'schema:' + name;
  let sh = ss.getSheetByName(name);
  if (!sh || !cache.get(k)) { // create missing tabs and add new columns (e.g. Division) automatically
    sh = sh || ss.insertSheet(name);
    if (sh.getRange(1, 1, 1, cols.length).getValues()[0].join('|') !== cols.join('|')) {
      sh.getRange(1, 1, sh.getMaxRows(), cols.length).setNumberFormat('@');
      sh.getRange(1, 1, 1, cols.length).setValues([cols]).setFontWeight('bold').setBackground('#1f3a5f').setFontColor('#ffffff');
      sh.setFrozenRows(1);
    }
    cache.put(k, '1', 21600);
  }
  return (SH_[name] = sh);
}

/* ───────────── Data-access helpers ───────────── */
function ss_() { return SS_ || (SS_ = CFG.SS_ID ? SpreadsheetApp.openById(CFG.SS_ID) : SpreadsheetApp.getActiveSpreadsheet()); }
function table_(name) {
  const sh = sheet_(name);
  const cols = COLS[name], n = Math.max(sh.getLastRow() - 1, 0);
  const vals = n ? sh.getRange(2, 1, n, cols.length).getValues() : [];
  const rows = vals.map((v, i) => { const o = {_row: i + 2}; cols.forEach((c, j) => o[c] = String(v[j])); return o; });
  return {sh: sh, cols: cols, rows: rows};
}
function put_(t, row, obj) {
  t.sh.getRange(row, 1, 1, t.cols.length).setValues([t.cols.map(c => obj[c] == null ? '' : String(obj[c]))]);
}
function audit_(user, action, entity, id, details) {
  sheet_(T.LOG).appendRow([iso_(), user, action, entity, id, details]);
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
  [T.REC, T.USR, T.LOG, T.SET].forEach(name => sheet_(name)); // creates tabs, headers and text formatting
  const t = table_(T.USR);
  if (t.rows.length) { Logger.log('Users already exist. Setup refreshed headers only.'); return; }
  const pw = 'Gso-' + Utilities.getUuid().slice(0, 8) + '7', salt = Utilities.getUuid();
  put_(t, 2, {Username: 'admin', FullName: 'System Administrator', Role: 'Admin', Cabinets: '*', Status: 'Active', Division: 'Admin Division',
    Salt: salt, Hash: hash_(pw, salt), CreatedAt: iso_(), LastLogin: ''});
  CacheService.getScriptCache().remove('users');
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
  CacheService.getScriptCache().remove('users');
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
  dropRecCache_();
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
      Status: 'Active', CreatedAt: now, CreatedBy: 'import', UpdatedAt: now, UpdatedBy: 'import', Version: '1', FileId: '', FileName: ''
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
