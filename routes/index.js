var express = require('express');
var router = express.Router();
const User=require('../Models/User');
const bcrypt=require('bcrypt');
const jwt=require('jsonwebtoken');
const auth=require('../Middleware/auth');
require('dotenv').config();

console.log(process.env.ACCESS_SECRET);
console.log(process.env.REFRES_SECRET);

const genRefreshToken= (userId)=>{
  return jwt.sign({userId},process.env.REFRES_SECRET,{expiresIn:'7d'});
}

/* GET home page. */
router.post('/register', async (req,res,next)=>{
    const {email,password,name}=req.body;
    const user= await User.findOne({email});
    const hashedPassword=await bcrypt.hash(password,10);
    if(user){
      res.status(400).json({message:'User already exists'});
    }
    const newUser=new User({
      name,
      email,
      password:hashedPassword
    })
    await newUser.save();
    const payload={id:newUser._id};
    const token=jwt.sign(payload,process.env.ACCESS_SECRET,{expiresIn:'1min'});
    res.status(201).json({message:"user susesfully registerd",token});
})

router.post('/login', async (req,res,next)=>{
  const {email,password}=req.body;
  const user=await User.findOne({email});
  if(!user){
    return res.status(400).json({message:'Invalid email or password'});
  }
  const isMatch=await bcrypt.compare(password,user.password);
  if(!isMatch){
    return res.status(400).json({message:'Invalid email or password'});
  }
  const payload={id:user._id};
  const token=jwt.sign(payload,process.env.ACCESS_SECRET,{expiresIn:'1min'});
  const refreshToken=genRefreshToken(payload.id);
  user.refreshToken=refreshToken;
  await user.save();

  return res.status(200).json({message:'Login successful',token,refreshToken});

})

router.post('/refresh-token', async(req,res,next)=>{
   const {refreshToken}=req.body;
   if(!refreshToken){
    return res.status(401).json({message:'Access denied. No token provided'});
   }
   const user =await User.findOne({refreshToken});
   if(!user){
    return res.status(401).json({message:'Invalid refresh token'});
   }
   
   try{
    const veryfied=jwt.verify(refreshToken,process.env.REFRES_SECRET);
    const payload={userId:veryfied.userId};
    const token=jwt.sign(payload,process.env.ACCESS_SECRET,{expiresIn:'1min'});
     return res.status(200).json({token});

   }catch(err){
    res.status(400).json({message:'Invalid token'});
   }
})

module.exports = router;
