const jwt = require('jsonwebtoken');
const secretKey = '123';

function authenticateToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ message: 'Unauthorized - Missing Authorization Header' });

    jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
        if (err) {
            console.error('Error verifying token:', err);
            return res.status(403).json({ message: 'Unauthorized - Invalid Token' });
        }

        console.log('Token from request:', token);
        console.log('Token from verification:', user);

        req.user = user;
        next();
    });
}
module.exports = authenticateToken;
