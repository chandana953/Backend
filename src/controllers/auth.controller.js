//2.api for user registration= req,res

const userModel = require('../models/user.model');
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

//need to generate jwt secert 
//jwtsecrets.com
/*What is a JWT Secret Key?
A JWT secret key is a private cryptographic key used to sign JSON Web Tokens */

async function registerUser(req, res) {

    const { username, email, password, role ="user" } = req.body;

    const isUserAlreadyExist = await userModel.findOne({ 
    $or: [
        {username},
        {email}
    ]
    })

    if(isUserAlreadyExist){
        return res.status(409).json({
            message:"user already exists"
        })
    }

    // Hash the password before saving it
    const hash = await bcrypt.hash(password, 10)


const user = await userModel.create({
    username,
    email,
    password : hash,
    role
})
/*after creating user -> create token*/
//after generating secret key we need to create token 

const token = jwt.sign({
    id:user._id,
    role: user.role,

}, process.env.JWT_SECRET)

//token generated is set in cookie
res.cookie("token", token)

res.status(201).json({
    message:"user created successfully",
    user:{
        id:user._id,
        username:user.username,
        email:user.email,
        role:user.role
    }
})
}

async function loginUser(req, res) {

    const {username,email, password} = req.body;

    const user = await userModel.findOne({
        $or:[
            {username},
            {email}
        ]
    })

    if(!user){
        return res.status(404).json({
            message:"Invalid credentials"
        })
    }

    // Compare the provided password with the hashed password
    const isMatch = await bcrypt.compare(password, user.password);

    if(!isMatch){
        return res.status(401).json({
            message:"Invalid credentials"
        })
    }



const token = jwt.sign({
    id:user._id,
    role: user.role,
}, process.env.JWT_SECRET)

//token generated is set in cookie
res.cookie("token", token)

res.status(200).json({
    message:"user logged in successfully",
    user:{
        id:user._id,
        username:user.username,
        email:user.email,
        role:user.role
    }
})

}

module.exports = {
    registerUser,
    loginUser
}