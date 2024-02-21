// server.js
import express from "express";
import configViewEngine from "./configs/viewEngine";
import webRouter from "./routes/web"; // Sửa đường dẫn import
import cors from 'cors';
const app = express();

// Cấu hình view engine
configViewEngine(app);
app.use(cors());
// Sử dụng router trực tiếp
app.use('/', webRouter);

const port = process.env.PORT || 8080;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
