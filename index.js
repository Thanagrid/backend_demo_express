require('dotenv').config();

const cookieParser = require('cookie-parser')
const express = require('express')
const app = express()
const port = 3030
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const { Pool } = require('pg')
const verifyToken = require('./auth');

// use
app.use(express.json())
app.use(cookieParser())

const jwt_secret_key = process.env.JWT_SECRET_KEY

// DB
const db = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'homeward_db_2_cloning',
  password: 'postgres',
  port: 5432,
})

// create hash password
app.post('/api/create/hash-password', async (req, res)=>{
   const {password} = req.body

   try{
      const hash = await bcrypt.hash(password, 10)
      return res.status(200).json({
         success: true,
         message: 'สร้าง hash password สำเร็จ',
         hash: hash
      })
   }catch(error){
      console.error(error);
      return {
         success: false,
         message: 'มีบางอย่างผิดพลาด โปรดลองอีกครั้งในภายหลัง',
      }
      
   }
})

// LOGIN
app.post('/api/login', async (req, res) => {
   const {username, password} = req.body

   try{
      const result = await db.query('SELECT * from "user" WHERE username = $1', [username])
      const user = result.rows[0]
      
      const match = await bcrypt.compare(password, user.password)
      if (!match) {
         return res.status(400).json({
            success: false,
            message: "ชื่อผู้ใช้ หรือรหัสผ่านไม่ถูกต้อง"
         })
      }

      // Create a token
      const user_token = jwt.sign({ user_id: user.user_id }, jwt_secret_key, { expiresIn: '6h' })

      res.status(200).json({
         success: true,
         message: 'เข้าสู่ระบบสำเร็จ',
         user_token: user_token
      })

   }catch(error){
      console.log(error);
      return res.status(400).json({
         success: false,
         message: "ชื่อผู้ใช้ หรือรหัสผ่านไม่ถูกต้อง"
      })
   }
})

// get user person
app.get('/api/get-user-person',verifyToken , async (req, res) => {
   const {user_id} = req.user
   
   try{

      const query = `SELECT 
      person.id_type, person.cid, person.ppn, person.pwd, person.profession_id, 
      lookup_title.short_value as title, person.firstname, person.lastname, "user".profile_url
      FROM "user" 
      LEFT JOIN person ON "user".user_id = person.user_id 
      LEFT JOIN lookup_title ON person.title = lookup_title.title 
      WHERE "user".user_id = $1
      `;

      const result = await db.query(query, [user_id])

      res.status(200).json({
         success: true,
         message: "ค้นหาข้อมูลบุคคลสำเร็จ",
         person: result.rows[0]
      })

   }catch(error){
      console.log(error);
      return res.status(400).json({
         success: false,
         message: "มีบางอย่างผิดพลาด โปรดลองอีกครั้งในภายหลัง"
      })
   }
})

// get user role list
app.get('/api/get-user-role',verifyToken , async (req, res) => {
   const {user_id} = req.user

   try{

      const result = await db.query(
         'SELECT role.role_id, role.role, role.hcode, provider.hname, role.health_region, role.is_blocked FROM role LEFT JOIN provider ON role.hcode = provider.hcode WHERE role.user_id = $1 ORDER BY role.created_at ASC'
         , [user_id]
      )

      res.status(200).json({
         success: true,
         message: "ค้นหารายการบทบาทสำเร็จ",
         role: result.rows
      })

   }catch(error){
      console.log(error);
      return res.status(400).json({
         success: false,
         message: "มีบางอย่างผิดพลาด โปรดลองอีกครั้งในภายหลัง"
      })
   }

})

// select role
app.post('/api/select-role', verifyToken, async (req, res) => {
    try {
        // 1. รับ user_id จาก Token (ที่ verifyToken แกะมาให้)
        const { user_id } = req.user;
        
        // 2. รับ role_id ที่ User เลือกส่งมาจาก Body
        const { role_id } = req.body;

        if (!role_id) {
            return res.status(400).json({ 
                success: false, 
                message: "กรุณาระบุ role_id" 
            });
        }

        // 3. Query ตรวจสอบว่า User คนนี้ มีสิทธิ์ใน Role ID นี้จริงหรือไม่
        // และดึงข้อมูลที่จำเป็นมาใส่ใน Token ใหม่เลย (role, hcode, health_region)
        const query = `
            SELECT role_id, role, hcode, health_region
            FROM "role" 
            WHERE user_id = $1 AND role_id = $2
        `;
        
        const result = await db.query(query, [user_id, role_id]);

        // ถ้าหาไม่เจอ แปลว่ามั่ว Role ID มา หรือไม่ใช่ Role ของตัวเอง
        if (result.rows.length === 0) {
            return res.status(403).json({
                success: false,
                message: "คุณไม่มีสิทธิ์เข้าใช้งานในบทบาทนี้"
            });
        }

        const roleData = result.rows[0];

        if(roleData.is_blocked === true){
            return res.status(403).json({
               success: false,
               message: "คุณไม่มีสิทธิ์เข้าใช้งานในบทบาทนี้"
            });
        }

        // 4. สร้าง JWT ใบใหม่ (Role Token)
        // ใส่ข้อมูล Context ให้ครบ เวลา Frontend ยิง API จะได้ไม่ต้องส่ง hcode มาอีก
        const role_token = jwt.sign(
            { 
                user_id: user_id, // คง user_id ไว้
                role_id: roleData.role_id,
                role: roleData.role,
                hcode: roleData.hcode,
                health_region: roleData.health_region
            }, 
            jwt_secret_key, 
            { expiresIn: '6h' } // อายุ 6 ชั่วโมง
        );

        // 5. ส่ง Role Token กลับไป (Frontend จะเอาไป Set Cookie ต่อ)
        res.json({
            success: true,
            message: "เลือกบทบาทสำเร็จ",
            role_token: role_token
        });

    } catch (error) {
        console.error('Select Role Error:', error);
        res.status(500).json({
            success: false,
            message: "เกิดข้อผิดพลาดภายในเซิร์ฟเวอร์"
        });
    }
});

// role test
app.get('/api/role-test', verifyToken, (req, res) => {
    
    // 1. ดึง role ของ user จริงๆ จาก Token
    // (เปลี่ยนจาก req.user.user.role เป็น req.user.role)
    const { role: user_role } = req.user;

    if(!user_role){
      return res.status(403).json({ success: false, message: "คุณไม่มี role" })
    }

    // 2. ดึง role ที่ต้องการเช็ค จาก URL Query Param (?role=...)
    // (เปลี่ยนจาก [role] เป็น { role })
    const { role: query_role } = req.query;

    console.log(`User Role: ${user_role}, Check Role: ${query_role}`);

    // กันเหนียว: กรณีไม่ได้ส่ง param มา
    if(!query_role) {
        return res.status(400).json({ success: false, message: "กรุณาระบุ role ที่ต้องการทดสอบ" });
    }

    // 3. เปรียบเทียบ
    if(user_role === query_role){
       return res.status(200).json({
          success: true,
          message: `ถูกต้อง! คุณคือ ${user_role} (ตรงกับที่ทดสอบ)`
       })
    }

    return res.status(403).json({
          success: false,
          message: `ไม่ผ่าน! คุณคือ ${user_role} (แต่กำลังทดสอบว่าเป็น ${query_role})`
    });
});


// listen
app.listen(port, async () => {
    try {
        // ลอง Query เวลาปัจจุบันดู เพื่อเช็คว่าต่อ DB ติดมั้ย
        await db.query('SELECT NOW()') 
        console.log('✅ Database connected successfully')
        console.log(`🚀 Server running at http://127.0.0.1:${port}`)
    } catch (error) {
        console.error('❌ Database connection failed:', error)
        // ถ้าต่อ DB ไม่ได้ ให้ปิด Server ไปเลย (จะได้ไม่หลอกตัวเองว่ารันผ่าน)
        process.exit(1) 
    }
})