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
let refreshTokens=[];

function authMiddleware(req,res,next){
    const token=req.cookies.accessToken;
    if(!token){
        return res.status(401).json({message:"Token Not Found"});
    }
    try{
        const decoded= jwt.verify(token,secret);
        const sessionExists=sessions.find(u=>u.sessionId===decoded.sessionId);

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
    const device=req.headers["user-agent"];
    const ip=req.ip;

    sessions.push({
        sessionId:sessionId,
        username:user.username,
        device:device,
        ip:ip,
        createdAt:new Date()
    })


    const accessToken=jwt.sign(
    {
        name:user.username,
        sessionId:sessionId
    },
    secret,
    {expiresIn:"1h"}
)

    const refreshToken=jwt.sign({
        name:user.username,
        sessionId:sessionId
    },
    secret,
    {expiresIn:"7d"}
) 
refreshTokens.push(refreshToken);

res.cookie("accessToken",accessToken,{
    httpOnly:true,
    sameSite:"strict",
    secure:false,
    maxAge:60*60*1000
});
res.cookie("refreshToken",refreshToken,{
    httpOnly:true,
    sameSite:"strict",
    secure:false,
    maxAge:7*24*60*60*1000
})

console.log(sessions);

res.status(200).json({message:"Login Successful"});

})

app.post("/refresh",(req,res)=>{
    const refreshToken=req.cookies.refreshToken;

    if(!refreshToken){
        return res.status(401).json({message:"Invalid refreshToken"});
    }

    if(!refreshTokens.includes(refreshToken)){
        return res.status(401).json({message:"refreshToken missing"});
    }
    try{
        const decoded=jwt.verify(refreshToken,secret);

        const sessionExists=sessions.find(s=>s.sessionId===decoded.sessionId)

    if(!sessionExists){
    return res.status(401).json({message:"Session expired"});
}

        const newAccessToken=jwt.sign({
            name:decoded.name,
            sessionId:decoded.sessionId
        },
        secret,
        {expiresIn:"1h"},
    );
    res.cookie("accessToken",newAccessToken,{
        httpOnly:true,
        sameSite:"strict",
        secure:false,
        maxAge:60*60*1000
    })
    res.json({message:"Refresh Token Generated"});
    }
    catch{
        return res.status(403).json({message:"Invalid refresh token"});

    }
})

app.post("/logout-device", authMiddleware, (req,res)=>{

    const {sessionId} = req.body;

    sessions = sessions.filter(
        s => s.sessionId !== sessionId
    );

    res.json({message:"Device logged out"});
});

app.post("/logout-all", authMiddleware,(req,res)=>{

    sessions = sessions.filter(
        s => s.username !== req.decoded.name
    );

    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");

    res.json({message:"Logged out from all devices"});
});

app.get("/sessions",authMiddleware,(req,res)=>{
    const userSession=sessions.filter(s=>s.username===req.decoded.name);

    res.json({sessions:userSession});
});

app.get("/logout",authMiddleware,(req,res)=>{

    const refreshToken=req.cookies.refreshToken;
    const sessionId=req.decoded.sessionId;

    refreshTokens = refreshTokens.filter(
        t => t !== refreshToken
    );
    
    sessions=sessions.filter(s=>s.sessionId!==sessionId)

    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");

    res.json({message:"Logout successfully"});
});



app.get("/users",authMiddleware,(req,res)=>{
    res.status(200).json({data:req.decoded});
})












app.listen(PORT,()=>{
    console.log(`server running at http://localhost:${PORT}`);
})