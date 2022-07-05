// Auth middleware - 3 arguments - req,res,callback function
// we have to send that token back to authenticate an access protected routes

const jwt = require("jsonwebtoken");
const config = require("config");

module.exports = function(req,res,next){ // next -> callback function

    // get token from header becoz in req body we will be sending the token when we try to access the protected routes
    const token = req.header('x-auth-token');

    // check if there is no token
    if(!token)
        return res.status(401).json({msg: "No Token, Autherization Denied"});

    // verify the token 
    try{
        const decoded = jwt.verify(token, config.get("jwtToken"));

        req.user = decoded.user; // now the req.user can be used anywhere to access the protected routes
        next();
    }catch(err){
        res.status(401).json({msg: "Token is not valid"});
    }
}