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
  database: 'homeward_db_v2_mockup',
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
      const result = await db.query('SELECT * from users WHERE username = $1', [username])
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
      lookup_title.short_value as title, person.firstname, person.lastname, users.profile_url
      FROM users 
      LEFT JOIN person ON users.user_id = person.user_id 
      LEFT JOIN lookup_title ON person.title = lookup_title.title 
      WHERE users.user_id = $1
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

      const query = `
      SELECT roles.role_id, roles.role, roles.hcode, provider.hname, roles.health_region, roles.is_blocked 
      FROM roles 
      LEFT JOIN provider ON roles.hcode = provider.hcode 
      WHERE roles.user_id = $1 
      ORDER BY roles.created_at ASC
      `

      const result = await db.query(
         query
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
            FROM roles 
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

// get all staff
app.get('/api/get-all-staff', verifyToken, async (req, res) => {
   try {
      const query = `
         SELECT 
            p.user_id::text as id,
            p.cid,
            COALESCE(lt.short_value, '') || p.firstname || ' ' || p.lastname as fullname,
            p.phone,
            p.phone,
            p.profession_id,
            string_agg(r.role::text, ', ') as roles,
            p.medical_expertise as specialty,
            p.created_at,
            u.email
         FROM person p
         LEFT JOIN lookup_title lt ON p.title = lt.title
         INNER JOIN roles r ON p.user_id = r.user_id
         LEFT JOIN users u ON p.user_id = u.user_id
         WHERE r.role::text ~* 'doctor|psychiatrist|pharmacist|nurse|physiotherapist|nutritionist|interdisciplinary|assistant|almoner|social|เภสัช|แพทย์|พยาบาล|สังคม'
         GROUP BY p.user_id, p.cid, lt.short_value, p.firstname, p.lastname, p.phone, p.profession_id, p.medical_expertise, p.created_at, u.email
      `;

      const result = await db.query(query);

      res.status(200).json({
         success: true,
         message: "ดึงข้อมูลบุคลากรทั้งหมดสำเร็จ",
         staffs: result.rows
      });

   } catch (error) {
      console.log(error);
      return res.status(500).json({
         success: false,
         message: "มีบางอย่างผิดพลาด โปรดลองอีกครั้งในภายหลัง"
      })
   }
})

// Helper function to handle patient queries with pagination
const runPatientQuery = async (req, res, baseQuery, successMessage, errorOrigin) => {
   try {
      // 0. Handle Sorting
      const sortDirection = req.query.sort === 'asc' ? 'ASC' : 'DESC';

      // 1. รับค่า page และ limit จาก Query Param (ถ้าไม่ส่งมา ให้ใช้ค่า Default)
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 10;
      const offset = (page - 1) * limit;

      // 2. สร้าง Query สำหรับนับจำนวนทั้งหมด (Total Count)
      // ใช้ subquery เพื่อรองรับ query ที่ซับซ้อน
      const countQuery = `SELECT COUNT(*) FROM (${baseQuery}) AS total`;
      const countResult = await db.query(countQuery);
      const totalCount = parseInt(countResult.rows[0].count, 10);
      const totalPages = Math.ceil(totalCount / limit);

      // 3. สร้าง Query สำหรับดึงข้อมูลจริง (Data with Pagination)
      // Append ORDER BY clause to the baseQuery before limiting
      const dataQuery = `${baseQuery} ORDER BY a.dateadm ${sortDirection} LIMIT $1 OFFSET $2`;
      const dataResult = await db.query(dataQuery, [limit, offset]);

      // 4. ส่งผลลัพธ์กลับ
      res.status(200).json({
         success: true,
         message: successMessage,
         data: {
            patients: dataResult.rows,
            pagination: {
               total_items: totalCount,
               total_pages: totalPages,
               current_page: page,
               items_per_page: limit
            }
         }
      });
   } catch (error) {
      console.error(`${errorOrigin} Error:`, error);
      res.status(500).json({
         success: false,
         message: "เกิดข้อผิดพลาดภายในเซิร์ฟเวอร์"
      });
   }
};

// get patient-all
app.get('/api/patient-stats', verifyToken, async (req, res) => {
   const getCount = async (query) => {
      const result = await db.query(query);
      return parseInt(result.rows[0].count, 10);
   };

   try {
      const query = `
         SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE d.van IS NULL) AS active,
            COUNT(*) FILTER (WHERE d.dischs = '1') AS recovered,
            COUNT(*) FILTER (WHERE d.dischargestatus = '2') AS improved,
            COUNT(*) FILTER (WHERE d.dischargestatus = '3') AS not_improved,
            COUNT(*) FILTER (WHERE d.dischargestatus = '9') AS death
         FROM admit a
         LEFT JOIN discharge d ON a.van = d.van
      `;

      const result = await db.query(query);
      const stats = result.rows[0];

      res.status(200).json({
         success: true,
         message: "ดึงข้อมูลสถิติผู้ป่วยสำเร็จ",
         stats: {
            total: parseInt(stats.total, 10),
            active: parseInt(stats.active, 10),
            recovered: parseInt(stats.recovered, 10),
            improved: parseInt(stats.improved, 10),
            not_improved: parseInt(stats.not_improved, 10),
            death: parseInt(stats.death, 10)
         }
      });

   } catch (error) {
      console.error('Get Patient Stats Error:', error);
      res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดภายในเซิร์ฟเวอร์" });
   }
});

// Helper Constants for SQL Queries
const BASE_SELECT_FIELDS = `
   p.cid,
   a.hn,
   a.an,
   p.firstname || ' ' || p.lastname as fullname,
   p.phone,
   a.dateadm as admit_time,
   d.datedsc as discharge_time
`;

const BASE_FROM_AND_JOINS = `
   FROM discharge d
   JOIN admit a ON d.van = a.van
   LEFT JOIN person p ON a.user_id = p.user_id
`;

// get admit patients
app.get('/api/get-admit-patients', verifyToken, async (req, res) => {
   const query = `
      SELECT 
         ${BASE_SELECT_FIELDS}
      FROM admit a
      LEFT JOIN person p ON a.user_id = p.user_id
      LEFT JOIN discharge d ON a.van = d.van
      WHERE d.van IS NULL
   `;
   await runPatientQuery(req, res, query, "ดึงข้อมูลผู้ป่วยที่กำลังรักษาสำเร็จ", "Get Admit Patients");
});

// get recovered patients (dischs = '1')
app.get('/api/get-recovered-patients', verifyToken, async (req, res) => {
   const query = `
      SELECT 
         ${BASE_SELECT_FIELDS}
      ${BASE_FROM_AND_JOINS}
      WHERE d.dischs = '1'
   `;
   await runPatientQuery(req, res, query, "ดึงข้อมูลผู้ป่วยที่หายป่วยสำเร็จ", "Get Recovered Patients");
});

// get improved patients (dischargestatus = '2')
app.get('/api/get-improved-patients', verifyToken, async (req, res) => {
   const query = `
      SELECT 
         ${BASE_SELECT_FIELDS}
      ${BASE_FROM_AND_JOINS}
      WHERE d.dischargestatus = '2'
   `;
   await runPatientQuery(req, res, query, "ดึงข้อมูลผู้ป่วยที่อาการทุเลาสำเร็จ", "Get Improved Patients");
});

// get not improved patients (dischargestatus = '3')
app.get('/api/get-not-improved-patients', verifyToken, async (req, res) => {
   const query = `
      SELECT 
         ${BASE_SELECT_FIELDS}
      ${BASE_FROM_AND_JOINS}
      WHERE d.dischargestatus = '3'
   `;
   await runPatientQuery(req, res, query, "ดึงข้อมูลผู้ป่วยที่อาการไม่ทุเลาสำเร็จ", "Get Not Improved Patients");
});

// get death patients (dischargestatus = '9')
app.get('/api/get-death-patients', verifyToken, async (req, res) => {
   const query = `
      SELECT 
         ${BASE_SELECT_FIELDS}
      ${BASE_FROM_AND_JOINS}
      WHERE d.dischargestatus = '9'
   `;
   await runPatientQuery(req, res, query, "ดึงข้อมูลผู้ป่วยที่เสียชีวิตสำเร็จ", "Get Death Patients");
});
