import express from "express";
import pool from "../configs/connectDb";
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const authenticateToken = require('../middleware/AuthenticateToken');
const multer = require('multer');
const path = require('path');

const secretKey = '123';
const router = express.Router();
router.use(express.json());
module.exports = router;


// Thiết lập multer storage
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/'); // Đường dẫn thư mục lưu trữ tệp
    },
    filename: function (req, file, cb) {
        const ext = path.extname(file.originalname);
        cb(null, `${file.fieldname}-${Date.now()}${ext}`);
    },
});
// Kiểm soát loại tệp được phép tải lên
const fileFilter = (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
        cb(null, true);
    } else {
        cb(new Error('Only image files are allowed!'), false);
    }
};

const upload = multer({ storage, fileFilter });


router.get('/api/user/:id', async (req, res) => {
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
            role: existingUsers[0].role,
        };

        res.json({ user, token });
    } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).json({ message: 'Internal system error' });
    }
});
// api/register
router.post('/api/register', async (req, res) => {
    const { username, fullname, email, password, address, phone } = req.body;

    try {
        // Check if the user exists
        const [existingUsers, fields] = await pool.execute('SELECT * FROM `users` WHERE username = ?', [username]);

        if (existingUsers.length > 0) {
            return res.status(400).json({ message: 'Username already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Add user with default role 'Customer'
        const [result, _] = await pool.execute(
            'INSERT INTO `users` (username, fullname, email, password, address, phone, role) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [username, fullname, email, hashedPassword, address, phone, 'Customer']
        );

        const userId = result.insertId;

        // Return registered user information
        const registeredUser = {
            id: userId,
            username,
            fullname,
            email,
            address,
            phone,
            role: 'Customer', // Default role
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
router.get('/api/blogs', async (req, res) => {
    try {
        // Truy vấn cơ sở dữ liệu để lấy dữ liệu từ bảng blog
        const [rows, fields] = await pool.execute('SELECT post_id, title, content, image FROM post');

        // Trả về dữ liệu lấy được từ cơ sở dữ liệu
        res.json({ posts: rows });
    } catch (error) {
        console.error('Error querying MySQL:', error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});
// Route API để lấy thông tin của một bài viết từ bảng blog theo ID
router.get('/api/blogs/:id', async (req, res) => {
    const postId = req.params.id;

    try {
        // Truy vấn cơ sở dữ liệu để lấy thông tin của bài viết theo ID
        const [rows, fields] = await pool.execute('SELECT title, content, image FROM post WHERE post_id = ?', [postId]);

        if (rows.length > 0) {
            const post = {
                title: rows[0].title,
                content: rows[0].content,
                image: rows[0].image
            };
            res.json(post);
        } else {
            res.status(404).json({ message: 'Blog not found' });
        }
    } catch (error) {
        console.error('Error querying MySQL:', error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});
// Endpoint API để lấy danh sách các bài viết khác dựa trên ID của bài viết hiện tại
router.get('/api/blogs/:id/other-blogs', async (req, res) => {
    const postId = req.params.id;

    try {
        // Truy vấn cơ sở dữ liệu để lấy danh sách các bài viết khác dựa trên ID
        const [rows, fields] = await pool.execute('SELECT post_id, title FROM `post` WHERE post_id != ? LIMIT 8', [postId]);

        // Trả về danh sách các bài viết khác
        res.json(rows);
    } catch (error) {
        console.error('Error querying MySQL:', error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});


router.post('/api/blogs', async (req, res) => {
    const { title, content, imageUrl } = req.body;

    try {
        // Thực hiện xử lý với imageUrl (ví dụ: lưu vào CSDL)
        const [result, _] = await pool.execute(
            'INSERT INTO `post` (title, content, image) VALUES (?, ?, ?)',
            [title, content, imageUrl]
        );

        if (result.affectedRows > 0) {
            res.status(200).json({ message: 'Blog post added successfully' });
        } else {
            res.status(400).json({ message: 'Failed to add blog post' });
        }
    } catch (error) {
        console.error('Error adding blog post:', error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

// Endpoint to edit an existing blog post
router.put('/api/blogs/:postId', async (req, res) => {
    const postId = req.params.postId;
    const { title, content, image } = req.body;

    try {
        // Update blog post in the database
        const [result, _] = await pool.execute(
            'UPDATE `post` SET title=?, content=?, image=? WHERE post_id=?',
            [title, content, image, postId]
        );

        if (result.affectedRows > 0) {
            res.status(200).json({ message: 'Blog post updated successfully' });
        } else {
            res.status(404).json({ message: 'Blog post not found' });
        }
    } catch (error) {
        console.error('Error updating blog post:', error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

// Endpoint to delete an existing blog post
router.delete('/api/blogs/:postId', async (req, res) => {
    const postId = req.params.postId;

    try {
        // Delete blog post from the database
        const [result, _] = await pool.execute('DELETE FROM `post` WHERE post_id=?', [postId]);

        if (result.affectedRows > 0) {
            res.status(200).json({ message: 'Blog post deleted successfully' });
        } else {
            res.status(404).json({ message: 'Blog post not found' });
        }
    } catch (error) {
        console.error('Error deleting blog post:', error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

// POST request để tìm kiếm bài viết theo tiêu đề
router.post('/search-blogs', async (req, res) => {
    const searchTerm = req.body.searchTerm;

    try {
        // Truy vấn cơ sở dữ liệu để tìm kiếm bài viết phù hợp với từ khóa tìm kiếm
        const [rows, fields] = await pool.execute('SELECT * FROM `post` WHERE title LIKE ?', [`%${searchTerm}%`]);

        res.json(rows); // Trả về kết quả tìm kiếm
    } catch (error) {
        console.error('Lỗi truy vấn cơ sở dữ liệu:', error);
        res.status(500).json({ message: 'Lỗi máy chủ nội bộ' });
    }
});


router.get('/api/quotation', async (req, res) => {
    try {
        // Truy vấn cơ sở dữ liệu để lấy dữ liệu từ bảng quotation
        const [rows, fields] = await pool.execute('SELECT title, content, date, price, status FROM `quotation`');

        // Trả về dữ liệu lấy được từ cơ sở dữ liệu
        res.json({ quotations: rows });
    } catch (error) {
        console.error('Error querying MySQL:', error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

router.post('/api/save-result', async (req, res) => {
    try {
        const {
            user_id,
            loai_nha,
            dich_vu_xay,
            muc_dau_tu,
            mat_tien,
            chieu_rong,
            chieu_dai,
            so_tang,
            ngach_hem,
            lung,
            tum,
            san_thuong,
            ban_cong,
            mong,
            tang_ham,
            mai,
            san_vuon,
            don_gia,
            dien_tich_mong,
            chi_phi_mong,
            dien_tich_ham,
            chi_phi_ham,
            dien_tich_mai,
            chi_phi_mai,
            dien_tich_toan_bo,
            thanh_tien_tang,
            dien_tich_lung,
            thanh_tien_lung,
            dien_tich_tum,
            thanh_tien_tum,
            dien_tich_ban_cong,
            chi_phi_ban_cong,
            dien_tich_san_vuon,
            chi_phi_san_vuon,
            tong_dien_tich,
            tong_chi_phi,
        } = req.body;

        // Query để thêm kết quả vào bảng 'calculationresult'
        const insertQuery = `
        INSERT INTO calculationresult (
          user_id,
          loai_nha,
          dich_vu_xay,
          muc_dau_tu,
          mat_tien,
          chieu_rong,
          chieu_dai,
          so_tang,
          ngach_hem,
          lung,
          tum,
          san_thuong,
          ban_cong,
          mong,
          tang_ham,
          mai,
          san_vuon,
          don_gia,
          dien_tich_mong,
          chi_phi_mong,
          dien_tich_ham,
          chi_phi_ham,
          dien_tich_mai,
          chi_phi_mai,
          dien_tich_toan_bo,
          thanh_tien_tang,
          dien_tich_lung,
          thanh_tien_lung,
          dien_tich_tum,
          thanh_tien_tum,
          dien_tich_ban_cong,
          chi_phi_ban_cong,
          dien_tich_san_vuon,
          chi_phi_san_vuon,
          tong_dien_tich,
          tong_chi_phi
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;

        const values = [
            user_id,
            loai_nha,
            dich_vu_xay,
            muc_dau_tu,
            mat_tien,
            chieu_rong,
            chieu_dai,
            so_tang,
            ngach_hem,
            lung,
            tum,
            san_thuong,
            ban_cong,
            mong,
            tang_ham,
            mai,
            san_vuon,
            don_gia,
            dien_tich_mong,
            chi_phi_mong,
            dien_tich_ham,
            chi_phi_ham,
            dien_tich_mai,
            chi_phi_mai,
            dien_tich_toan_bo,
            thanh_tien_tang,
            dien_tich_lung,
            thanh_tien_lung,
            dien_tich_tum,
            thanh_tien_tum,
            dien_tich_ban_cong,
            chi_phi_ban_cong,
            dien_tich_san_vuon,
            chi_phi_san_vuon,
            tong_dien_tich,
            tong_chi_phi,
        ];

        db.query(insertQuery, values, (err, result) => {
            if (err) {
                console.error('Error saving result to MySQL:', err);
                res.status(500).json({ success: false, message: 'Internal Server Error' });
            } else {
                res.json({ success: true, message: 'Result saved successfully' });
            }
        });
    } catch (error) {
        console.error('Error saving result:', error);
        res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
});


router.post('/saveResult', (req, res) => {
    const data = req.body; // Make sure to use body-parser middleware or equivalent

    // Assuming you have a users table with user_id and a results table with the specified columns
    const query = 'INSERT INTO calculationresult SET ?';
    db.query(query, data, (err, result) => {
        if (err) {
            console.error('Error saving result to database:', err);
            res.status(500).send('Internal Server Error');
        } else {
            console.log('Result saved successfully');
            res.status(200).send('Result saved successfully');
        }
    });
});
export default router;
