const { rejects } = require('assert')
const mysql = require('mysql')
const { resolve } = require('path')

require('dotenv').config();


const pool = mysql.createPool( 
{   
    connectionLimit: 10,
    host:"localhost",
    user :"root",
    password:"1234",
    port:3306,
    database:"Sample",
    createDatabaseTable: false
})

let db = {}

db.getUser = () => {
    return new Promise(
        (resolve, reject) =>
        {
            pool.query('SELECT * FROM User',(error, user) =>
            {
                if(error)
                {
                    return reject(error)
                }
                return resolve(user)
            });
        }
    );
}

//Get user by email/username

db.getUserByUsername = (username) =>
{
    return new Promise((resolve, reject) => 
    {
        pool.query("SELECT * FROM User WHERE username = ?", [username], (error, users) =>
        {
            if(error)
            {
                return reject(error)
            }
            if(users.length >= 1)
            {
                return resolve(users[0])
            }
            
            console.log(`The username is incorect!`)

        
            return reject(error)
           
        })
    })
}

db.insertUser = (username, hash, salt) => 
{
    return new Promise((resolve, reject) =>
    {
        pool.query("INSERT INTO User (username, hash, salt) VALUES (?, ?, ?)", [username, hash, salt], (error, result)=>
        {
            if(error)
            {
                return reject(error)
            }
            return resolve(result)
        })
    })
}

db.insertAdmin = (username, hash, salt) => 
{
    return new Promise((resolve, reject) =>
    {
        pool.query("INSERT INTO User (username, hash, salt, isAdmin) VALUES (?, ?, ?, ?)", [username, hash, salt, true], (error, result)=>
        {
            if(error)
            {
                return reject(error)
            }
            return resolve(result)
        })
    })
}

module.exports = db;