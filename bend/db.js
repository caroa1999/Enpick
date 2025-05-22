// db.js (프로젝트 최상위 bend 폴더에 위치)
const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'wlsehtro1!',   // ← 실제 MySQL 패스워드로!
  database: 'enpick_db',    // ← 실제 DB 이름!
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

module.exports = pool;
