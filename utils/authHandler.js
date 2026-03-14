let jwt = require('jsonwebtoken')
let userController = require("../controllers/users")
let { publicKey } = require('./generateKeys')
module.exports = {
    checkLogin: async function (req, res, next) {
        try {
            let token = req.headers.authorization;
            if (!token || !token.startsWith('Bearer')) {
                return res.status(404).send("ban chua dang nhap")
            }
            token = token.split(" ")[1];
            let result = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
            if (result.exp * 1000 > Date.now()) {
                let user = await userController.FindUserById(result.id);
                if (user) {
                    req.user = user
                    return next()
                } else {
                    return res.status(404).send("ban chua dang nhap")
                }
            } else {
                return res.status(404).send("ban chua dang nhap")
            }
        } catch (error) {
            return res.status(404).send("ban chua dang nhap")
        }
    }
}