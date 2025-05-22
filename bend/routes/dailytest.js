// routes/dailytest.js
const express = require('express');
const router = express.Router();
const db = require('../db'); // DB 연결 불러오기

router.post('/submit', async (req, res) => {
  const { user_id, correct_count, total_count, accuracy } = req.body;
  const today = new Date().toISOString().slice(0, 10);

  if (!user_id || !total_count) {
    return res.status(400).json({ message: '필수 값 누락' });
  }
  try {
    // 이미 오늘 기록이 있으면 업데이트, 없으면 새로 생성 (upsert)
    await db.query(
      `INSERT INTO daily_test_result (user_id, date, correct_count, total_count, accuracy)
       VALUES (?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE correct_count=?, total_count=?, accuracy=?, updated_at=NOW()`,
      [
        user_id, today, correct_count, total_count, accuracy,
        correct_count, total_count, accuracy
      ]
    );
    res.json({ message: '저장 완료' });
  } catch (e) {
    console.error('[랭킹 쿼리 에러]', e);
    res.status(500).json({ message: 'DB 저장 오류' });
  }
});


// [랭킹 조회] 각 유저의 dailytest 최고 정답률 Top 20
router.get('/rank', async (req, res) => {
  try {
    const sql = `
      SELECT u.id AS user_id,
             u.full_name,
             u.email,
             MAX(dtr.accuracy) AS accuracy
      FROM users u
      JOIN daily_test_result dtr ON u.id = dtr.user_id
      GROUP BY u.id, u.full_name, u.email
      ORDER BY accuracy DESC
      LIMIT 20
    `;
    const [rows] = await db.query(sql);
    res.json(rows);
  } catch (err) {
    console.error('[랭킹 API 오류]', err);
    res.status(500).json({ error: '랭킹 조회 실패' });
  }
});


module.exports = router;
