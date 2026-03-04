const express=require("express");
const bcrypt=require("bcrypt");
const jwt=require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const app=express();

const PORT=5500;

const secret="12345"

app.use(express.json());
app.use(cookieParser());

let users=[];
let sessions=[];

function authMiddleware(req,res,next){
    const token=req.cookies.token;
    if(!token){
        return res.status(401).json({message:"Token Not Found"});
    }
    try{
        const isVerified= jwt.verify(token,secret);
        req.decoded=isVerified;
        next();
    }
    catch(err){
        return res.status(401).json({message:"Invalid token"});
    }
    const sessionExists=sessions.find(u=>u.sessionId===isVerified.sessionId);

    if(!sessionExists){
        return res.status(401).json({message:"Session expired"});
    }
}


app.post("/register",async(req,res)=>{
    const {username,password}=req.body;
    if(!username || !password){
        return res.status(400).json({message:"username and password need"});
    }
    const hashedPassword=await bcrypt.hash(password,12);
    users.push({
        username:username,
        hashedPassword:hashedPassword
    })
    res.status(200).json({message:"registered succesfully"});
})

app.post("/login",async(req,res)=>{
    const {username,password}=req.body;

    const user=users.find(u=>u.username===username);

    if(!user){
        return res.status(400).json({message:"user not found"});
    }

    const matchPassword=await bcrypt.compare(password,user.hashedPassword);

    if(!matchPassword){
        return res.status(400).json({message:"Invalid credentials"});
    }
    const sessionId=Date.now().toString();

    sessions.push({
        sessionId:sessionId,
        username:user.username,
        createdAt:new Date()
    })


    const token=jwt.sign(
    {
        name:user.username,
        sessionId:sessionId
    },
    secret,
    {expiresIn:"1h"}
)
res.cookie("token",token,{
    httpOnly:true,
    sameSite:"strict",
    secure:false,
    maxAge:60*60*1000
});

res.status(200).json({message:"Login Successful"});

})

app.get("/users",authMiddleware,(req,res)=>{
    res.status(200).json({data:req.decoded});
})












app.listen(PORT,()=>{
    console.log(`server running at http://localhost:${PORT}`);
})