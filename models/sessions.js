const mongoose=require("mongoose");

const sessions= new mongoose.Schema({
    sessionId:{
        type:String,
        required:true,
        unique:true
    },
    username:{
        type:String,
        required:true,
        unique:true
    },
    device:{
        type:String,
        required:true,
    },
    ip:{
        type:String,
        required:true,
    },
    date:{
        type:Date,
        default:Date.now
    },
})

module.exports=mongoose.model("Session",sessions);