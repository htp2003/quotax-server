import express from "express";
import pool from "../configs/connectDb";
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const authenticateToken = require('../middleware/AuthenticateToken');


const secretKey = '123';
const router = express.Router();
router.use(express.json());




module.exports = router;
router.get('/api/user/:id', authenticateToken, async (req, res) => {
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
        const [existingUsers, fields] = await pool.execute('SELECT * FROM `users` WHERE username = ?', [username]);

        if (existingUsers.length === 0) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        const passwordMatch = await bcrypt.compare(password, existingUsers[0].password);

        if (!passwordMatch) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        // Generate a JWT token
        const token = jwt.sign(
            { userId: existingUsers[0].id, username: existingUsers[0].username },
            secretKey,
            { expiresIn: '1h' }
        );

        // Return user data and token
        const user = {
            id: existingUsers[0].user_id,
            username: existingUsers[0].username,
            fullname: existingUsers[0].fullname,
            email: existingUsers[0].email,
            phone: existingUsers[0].phone,
            address: existingUsers[0].address,

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

router.post('/api/update-profile', async (req, res) => {
    const userId = req.body.userId; // Sử dụng userId trực tiếp từ request body

    const { email, fullname, address, phone } = req.body;

    try {
        // Thực hiện cập nhật các trường chỉ định cho người dùng trong cơ sở dữ liệu
        const [result, _] = await pool.execute(
            'UPDATE `users` SET email = ?, fullname = ?, address = ?, phone = ? WHERE user_id = ?',
            [email, fullname, address, phone, userId]
        );

        if (result.affectedRows > 0) {
            // Lấy thông tin người dùng sau khi cập nhật từ cơ sở dữ liệu
            const [updatedUser, _] = await pool.execute(
                'SELECT * FROM `users` WHERE user_id = ?',
                [userId]
            );

            res.status(200).json({ message: 'Profile updated successfully', user: updatedUser[0] });
        } else {
            res.status(400).json({ message: 'Failed to update profile' });
        }
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ message: 'Internal system error' });
    }
});

// Endpoint để lấy tất cả bài viết
router.get('/api/posts', async (req, res) => {
    try {

        const posts = await db.query('SELECT * FROM post');

        res.json({ posts });
    } catch (error) {
        console.error('Error fetching posts:', error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

router.post('/api/change-password', authenticateToken, async (req, res) => {
    const userId = req.user.userId; // Lấy userId từ token
    const { currentPassword, newPassword, confirmPassword } = req.body;

    try {
        // Lấy thông tin người dùng từ database để kiểm tra mật khẩu hiện tại
        const [userRows, _] = await pool.execute('SELECT * FROM `users` WHERE user_id = ?', [userId]);

        if (userRows.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        const user = userRows[0];
        const isPasswordMatch = await bcrypt.compare(currentPassword, user.password);

        if (!isPasswordMatch) {
            return res.status(401).json({ message: 'Current password is incorrect' });
        }

        // Nếu mật khẩu hiện tại đúng, thực hiện cập nhật mật khẩu mới
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        const [updateResult, __] = await pool.execute(
            'UPDATE `users` SET password = ? WHERE user_id = ?',
            [hashedPassword, userId]
        );

        if (updateResult.affectedRows > 0) {
            return res.status(200).json({ message: 'Password changed successfully' });
        } else {
            return res.status(500).json({ message: 'Failed to update password' });
        }
    } catch (error) {
        console.error('Error changing password:', error);
        return res.status(500).json({ message: 'Internal Server Error' });
    }
});





export default router;
