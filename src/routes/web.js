import express from "express";
import pool from "../configs/connectDb";
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const secretKey = '123';
const router = express.Router();
router.use(express.json());



// Endpoint API để lấy danh sách người dùng
router.get('/api/users', async (req, res) => {
    try {
        const [rows, fields] = await pool.execute('SELECT * FROM `users`');
        console.log('rows', rows);

        const data = rows.map((row) => ({
            id: row.user_id,
            name: row.fullname,
            email: row.email,
            phone: row.phone,
            address: row.address,
        }));

        res.json({ data });
    } catch (error) {
        console.error('Error querying MySQL:', error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

// Endpoint API để lấy thông tin của một người dùng theo ID
router.get('/api/users/:id', async (req, res) => {
    const userId = req.params.id;

    try {


        const [rows, fields] = await pool.execute('SELECT * FROM `users` WHERE user_id = ?', [userId]);

        if (rows.length > 0) {
            const user = {
                id: rows[0].user_id,
                name: rows[0].fullname,
                username: rows[0].username,
                email: rows[0].email,
                phone: rows[0].phone,
                address: rows[0].address,
            };
            res.json({ user });
        } else {
            res.status(404).json({ message: 'User not found' });
        }
    } catch (error) {
        console.error('Error querying MySQL:', error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

// Endpoint API for user login
router.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Find the user by username
        const [existingUsers, fields] = await pool.execute('SELECT * FROM `users` WHERE username = ?', [username]);

        // Check if the user exists
        if (existingUsers.length === 0) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        // Compare the provided password with the hashed password in the database
        const passwordMatch = await bcrypt.compare(password, existingUsers[0].password);

        if (!passwordMatch) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        // Generate a JWT token
        const token = jwt.sign(
            { userId: existingUsers[0].id, username: existingUsers[0].username },
            secretKey,
            { expiresIn: '1h' } // Set expiration time for the token (1 hour in this example)
        );

        // Return user data and token
        const user = {
            id: existingUsers[0].id,
            username: existingUsers[0].username,
            fullname: existingUsers[0].fullname,
        };

        res.json({ user, token });
    } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).json({ message: 'Internal system error' });
    }
});


router.post('/api/register', async (req, res) => {
    const { username, fullname, email, password, address, phone } = req.body;

    try {
        // check if the user exists
        const [existingUsers, fields] = await pool.execute('SELECT * FROM `users` WHERE username = ?', [username]);

        if (existingUsers.length > 0) {
            return res.status(400).json({ message: 'Username already exists' });
        }

        // hash
        const hashedPassword = await bcrypt.hash(password, 10);

        // add user
        const [result, _] = await pool.execute(
            'INSERT INTO `users` (username, fullname, email, password, address, phone) VALUES (?, ?, ?, ?, ?, ?)',
            [username, fullname, email, hashedPassword, address, phone]
        );

        const userId = result.insertId;

        // Trả về thông tin người dùng đã đăng ký
        const registeredUser = {
            id: userId,
            username,
            fullname,
            email,
            address,
            phone,
        };

        res.status(201).json({ user: registeredUser, message: 'User registered successfully' });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ message: 'Internal system error' });
    }
});




export default router;
