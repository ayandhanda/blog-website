const User = require('../model/User');
const Blog = require('../model/Blog');
const Token = require('../model/Token');
const bcrypt = require('bcryptjs');
const saltRounds = 10;
const crypto = require("crypto");
const SendEmail = require("../utils/util");
const dotenv = require('dotenv').config();
const {otpGenerator} = require('../utils/otpgenerator');

module.exports.Login = async (req,res) => {
    const {Username,Password} = req.body;
    let user = await User.findOne({ Username: Username });
    if (user.is_verify) {
        bcrypt.compare(Password, user.Password, (err, result) => {
            if (result) {
                req.session.user = user;
                req.session.isLoggedIn = true;
                if (user.Admin) {
                    res.redirect('/admin');
                }
                else {
                    res.redirect('/');
                }
            }
            else {
                res.send("Invalid Password");
            }
        })
    }
    else {
        res.send("User not found");
    }
}

module.exports.LoginPage = (req,res) => {
    if (req.session.isLoggedIn) {
        res.redirect('/profile')
    }
    else{
        res.render('login.hbs');
    }
}

module.exports.RegisterPage = (req,res) => {
    if (!req.session.isLoggedIn) {
        res.render('register.hbs');
    }
    else{
        res.redirect('/admin');
    }
}

module.exports.Register = async (req,res) => {
    const { Username, Password } = req.body;
    const checkuser = await User.findOne({ Username: Username });
    if (checkuser) {
        res.send("User already registered");
    }
    else {
        bcrypt.hash(Password, saltRounds).then(async function (hash) {
            // Store hash in your password DB.
            const newUser = new User({ Username, Password: hash });
            await newUser.save();
            const otp = otpGenerator();
            let token = await new Token({
                userId: newUser._id,
                token: crypto.randomBytes(32).toString("hex"),
                otp: otp
            }).save();
            const message = `Verify your account using this otp : ${otp}

            ${process.env.BASE_URL}user/verify/${newUser.id}/${token.token}`;
            await SendEmail.SendEmail(newUser.Username, "Verify Email", message);
            res.send("verify your email by clicking link send to your email");
        });
    }
}

module.exports.AdminPage = async (req,res) => {
    if (req.session.isLoggedIn) {
        if(req.session.user.Admin==true){
            let blogs = await Blog.find({});
            res.render('adminpages/index.hbs',{blogs,user: req.session.user});
        }
    }
    else{
        res.redirect('/');
    }
}

module.exports.Logout = (req, res) => {
    req.session.isLoggedIn=false;
    res.redirect('/');
}

module.exports.CategoryPage = (req,res) => {
    if (req.session.isLoggedIn) {
        res.render('category.hbs',{user:req.session.user});
    }
    else{
        res.render('category.hbs');
    }
}

module.exports.Category = async(req,res) => {
    const {category} = req.body;
    if (req.session.isLoggedIn) {
        let blogs = await Blog.find({category:category,is_verify:true});
        res.render('category.hbs',{blogs:blogs,user:req.session.user});
    }
    else{
        let blogs = await Blog.find({category:category,is_verify:true});
        res.render('category.hbs',{blogs:blogs,category:category});
    }
}

module.exports.ProfilePage = async (req, res) => {
    if (req.session.isLoggedIn) {
        console.log(req.session.user._id)
        const userblogs = await Blog.find({ user_id: req.session.user._id });
        res.render('profile', { user: req.session.user, blogs: userblogs });
    }
    else {
        res.redirect('/');
    }
}

module.exports.Admin = async (req, res) => {
    const { id } = req.params;
    const { is_verify } = req.query;
    await Blog.findByIdAndUpdate(id, { is_verify: is_verify });
}