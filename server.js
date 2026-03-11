const express=require("express");
const bcrypt=require("bcrypt");
const jwt=require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const connectDB=require("./config/db");
const Sessions=require("./models/sessions");
const User=require("./models/user");

require("dotenv").config();

const app=express();
connectDB();

const PORT=process.env.PORT;


app.use(express.json());
app.use(cookieParser());


async function authMiddleware(req,res,next){
    const token=req.cookies.accessToken;
    if(!token){
        return res.status(401).json({message:"Token Not Found"});
    }
    try{
        const decoded= jwt.verify(token,process.env.JWT_SECRET);
        const sessionExists=await Sessions.findOne({
            sessionId:decoded.sessionId
        });

        if(!sessionExists){
        return res.status(401).json({message:"Session expired"});
    }

        req.decoded=decoded;
        next();
    }
    catch(err){
        return res.status(401).json({message:"Invalid token"});
    }

    
}


app.post("/register",async(req,res)=>{
    const {username,password}=req.body;
    if(!username || !password){
        return res.status(400).json({message:"username and password need"});
    }

    const existingUser=await User.findOne({username});

    if(existingUser){
        return res.status(400).json({message:"User already exists"});
    }
    const hashedPassword=await bcrypt.hash(password,12);
    const user=new User({
        username,
        hashedPassword
    });
    await user.save();
    res.status(200).json({message:"registered succesfully"});
})

app.post("/login",async(req,res)=>{
    const {username,password}=req.body;

    const user=await User.findOne({username});

    if(!user){
        return res.status(400).json({message:"user not found"});
    }

    const matchPassword=await bcrypt.compare(password,user.hashedPassword);

    if(!matchPassword){
        return res.status(400).json({message:"Invalid credentials"});
    }
    const sessionId=Date.now().toString();
    const device=req.headers["user-agent"];
    const ip=req.ip;

    const session=new Sessions({
        sessionId,
        username,
        device,
        ip

    })
    await session.save();


    const accessToken=jwt.sign(
    {
        name:user.username,
        sessionId:sessionId
    },
    process.env.JWT_SECRET,
    {expiresIn:"1h"}
)


res.cookie("accessToken",accessToken,{
    httpOnly:true,
    sameSite:"strict",
    secure:false,
    maxAge:60*60*1000
});

res.status(200).json({message:"Login Successful"});

})

app.get("/sessions",authMiddleware,async(req,res)=>{
    const sessions= await Sessions.find({
        username:req.decoded.name
    })

    res.json({sessions});
});

app.post("/logout",authMiddleware,async(req,res)=>{

    const sessionId=req.decoded.sessionId;

    await Sessions.deleteOne({sessionId})

    res.clearCookie("accessToken");

    res.json({message:"Logout successfully"});
});



app.get("/users",authMiddleware,(req,res)=>{
    res.status(200).json({data:req.decoded});
})








app.listen(PORT,()=>{
    console.log(`server running at http://localhost:${PORT}`);
})