let express = require('express')
let router = express.Router()
let userController = require('../controllers/users')
let { RegisterValidator, ChangePasswordValidator, validatedResult } = require('../utils/validator')
let bcrypt = require('bcrypt')
let jwt = require('jsonwebtoken')
const { checkLogin } = require('../utils/authHandler')
const { privateKey } = require('../utils/generateKeys')

router.post('/register', RegisterValidator, validatedResult, async function (req, res, next) {
    try {
        let { username, password, email, role } = req.body;
        if (!role) {
            return res.status(400).send({
                message: "role là bắt buộc"
            })
        }
        let newUser = await userController.CreateAnUser(
            username, password, email, role
        )
        res.send(newUser)
    } catch (error) {
        res.status(400).send({
            message: error.message
        })
    }
})
router.post('/login', async function (req, res, next) {
    let { username, password } = req.body;
    let user = await userController.FindUserByUsername(username);
    if (!user) {
        res.status(404).send({
            message: "thong tin dang nhap khong dung"
        })
        return;
    }
    if (!user.lockTime || user.lockTime < Date.now()) {
        if (bcrypt.compareSync(password, user.password)) {
            user.loginCount = 0;
            await user.save();
            let token = jwt.sign({
                id: user._id,
            }, privateKey, {
                algorithm: 'RS256',
                expiresIn: '1h'
            })
            res.send(token)
        } else {
            user.loginCount++;
            if (user.loginCount >= 3) {
                user.loginCount = 0;
                user.lockTime = new Date(Date.now() + 60 * 60 * 1000)
            }
            await user.save();
            res.status(404).send({
                message: "thong tin dang nhap khong dung"
            })
        }
    } else {
        res.status(404).send({
            message: "user dang bi ban"
        })
    }

})
router.get('/me',checkLogin, function (req,res,next) {
    res.send(req.user)
})

router.post('/changepassword', checkLogin, ChangePasswordValidator, validatedResult, async function (req, res, next) {
    try {
        let { oldpassword, newpassword } = req.body;

        let user = req.user;

        if (!bcrypt.compareSync(oldpassword, user.password)) {
            return res.status(400).send({
                message: "Mật khẩu cũ không đúng"
            })
        }

        user.password = newpassword;
        await user.save();

        res.send({
            message: "Đổi mật khẩu thành công"
        })

    } catch (error) {
        res.status(400).send({
            message: error.message
        })
    }
})

module.exports = router;