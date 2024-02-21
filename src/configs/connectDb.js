// Get the client
import mysql from 'mysql2/promise';
import dotenv from 'dotenv';

dotenv.config();
console.log('Creaating a connection pool...');
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    database: process.env.DB_DATABASE || 'housing_quotation_2',
});



export default pool;