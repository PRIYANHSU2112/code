const jwt=require('jsonwebtoken');

const genrateToken=(req,res,next)=>{
    const token =jwt.header('x-auth-token');
    if(!token){
        return res.status(401).json({message:'Access denied. No token provided'});
    }
    try{
        const veryfied=jwt.verify(token,process.env.JWT_SECRET);
        req.user=veryfied;
        next();
    }catch(err){
        res.status(400).json({message:'Invalid token'});
    }

}

module.exports=genrateToken;