// Marks every account approved. Run only while the service is stopped (it writes the DB file directly).
const initSqlJs = require('sql.js'), fs = require('fs'), path = require('path');
const dbPath = path.join(__dirname, 'data', 'recruiter.db');
initSqlJs().then(SQL => {
  const db = new SQL.Database(fs.readFileSync(dbPath));
  db.run("UPDATE users SET approved = 1 WHERE approved = 0");
  const rows = db.exec("SELECT username, role, approved FROM users");
  fs.writeFileSync(dbPath, Buffer.from(db.export()), { mode: 0o600 });
  console.log('accounts:', rows.length ? rows[0].values.map(r => `${r[0]}(${r[1]}${r[2] ? '' : ', pending'})`).join(', ') : 'none');
});
