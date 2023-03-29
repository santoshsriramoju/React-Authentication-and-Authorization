const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
require('dotenv').config({path:"./config.env"})

app.use(express.json())

const users = [
    {
        id: "1",
        username: 'john',
        password: "John0908",
        isAdmin: true
    },
    {
        id: "2",
        username: 'jane',
        password: "Jane0908",
        isAdmin: false
    }
]

let refreshTokens = [];

app.post("/api/refresh", (req, res) => {
    //Take the refresh token from the user
    const refreshToken = req.body.token;
    console.log("refreshToken------------",refreshToken)

    //Send error if there is no token or it's invalid
    if (!refreshToken) return res.status(401).json("You are not authenticated");
    if (!refreshTokens.includes(refreshToken)) {
        return res.status(403).json("Refresh token is not valid");
    }
    jwt.verify(refreshToken,process.env.SECRET_KEY_REFRESH, (err, user) => {
        err && console.error(err);
        refreshTokens = refreshTokens.filter(token => token !== refreshToken);
        console.log("refreshtokens", refreshTokens);

        const newAccessToken = generateAccessToken(user);
        const newRefreshToken = generateRefreshToken(user);

        refreshTokens.push(newRefreshToken);

        res.status(200).json({
            accessToken: newAccessToken,
            refreshToken: newRefreshToken
        })
    })

})

const generateAccessToken = (user) => {
    return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, process.env.SECRET_KEY_ACCESS, {
        expiresIn: "30s"
    });
}

const generateRefreshToken = (user) => {
    return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, process.env.SECRET_KEY_REFRESH);
}

app.post("/api/login", (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => {
        return u.username === username && u.password === password;
    });

    if (user) {
        //Generate an access token
        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);

        refreshTokens.push(refreshToken);

        return res.status(200).json({
            username: user.username,
            isAdmin: user.isAdmin,
            accessToken,
            refreshToken
        })
    } else {
        return res.status(400).json("Invalid credentials")
    }
})

const verify = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(" ")[1];
        jwt.verify(token, process.env.SECRET_KEY_ACCESS, (err, user) => {
            if (err) {
                return res.status(403).json("Token is not valid");
            }
            req.user = user;
            next();
        });
    } else {
        res.status(401).json("You are not authorized");
    }
};

app.delete("/api/users/:userId", verify, (req, res) => {
    if (req.params.userId === req.user.id || req.user.isAdmin) {
        res.status(200).json("User has been deleted")
    } else {
        res.status(403).json("You are not authorized to delete");
    }
})

app.post("/api/logout",verify,(req,res)=>{
    const refreshToken = req.body.token;
    refreshTokens = refreshTokens.filter(token => token !== refreshToken);
    res.status(200).json("You logged out successfully");
})

app.listen(5000, () => console.log("Backend server is running"))