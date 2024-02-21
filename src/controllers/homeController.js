import pool from "../configs/connectDb";


const handleHelloWorld = async (req, res) => {
    let data = [];
    // connection.query(
    //     'SELECT * FROM `users`',
    //     function (err, results, fields) {
    //         results.map((row) => {
    //             data.push({
    //                 id: row.user_id,
    //                 name: row.fullname,
    //                 email: row.email,
    //                 phone: row.phone,
    //                 address: row.address,
    //             });
    //         })

    //         // return res.render("home.ejs", { dataUser: JSON.stringify(data) });
    //     });

    const [rows, fields] = await pool.execute('SELECT * FROM `users`');
    console.log('rows', rows);
}
const handleUserPage = (req, res) => {
    return res.render("user.ejs");
}

module.exports = {
    handleHelloWorld,
    handleUserPage
}