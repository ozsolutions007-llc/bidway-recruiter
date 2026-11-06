// Usage: node set_role.js <username> <admin|user>   (run only while the service is stopped)
const initSqlJs = require("sql.js"), fs = require("fs"), path = require("path");
const [,, username, role] = process.argv;
if (!username || !["admin","user"].includes(role)) { console.error("usage: node set_role.js <username> <admin|user>"); process.exit(1); }
const dbPath = path.join(__dirname, "data", "recruiter.db");
initSqlJs().then(SQL => {
  const db = new SQL.Database(fs.readFileSync(dbPath));
  db.run("UPDATE users SET role = ? WHERE username = ?", [role, username]);
  const r = db.exec("SELECT username, role FROM users WHERE username = ?", [username]);
  fs.writeFileSync(dbPath, Buffer.from(db.export()), { mode: 0o600 });
  console.log(r.length ? r[0].values[0].join(" is now ") : "no such user: " + username);
});
