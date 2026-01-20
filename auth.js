const jwt = require('jsonwebtoken');

const verifyToken = (req, res, next) => {
    // 1. ดึงค่าจาก Header ที่ชื่อ Authorization
    const authHeader = req.headers['authorization'];
    
    // 2. เช็คว่ามีค่าส่งมาไหม และต้องขึ้นต้นด้วย Bearer
    // authHeader หน้าตาประมาณ: "Bearer <TOKEN_STRING>"
    const token = authHeader && authHeader.split(' ')[1]; 

    if (!token) {
        return res.status(401).json({ 
         success: false,
         message: 'ไม่พบ Token' 
      });
    }

    // 3. Verify Token
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ 
               success: false,
               message: "Token ไม่ถูกต้อง หรือหมดอายุ"
            });
        }

        // 4. สำคัญ! แปะข้อมูล user ที่แกะได้ลงไปใน req เพื่อให้ Route ถัดไปใช้ต่อได้
        req.user = decoded; 
        
        next(); // ไปต่อ
    });
};

module.exports = verifyToken;