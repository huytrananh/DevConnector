const express = require('express')
const router = express.Router()
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const config = require('config')
const { check, validationResult } = require('express-validator')
const auth = require('../../middleware/auth')

const User = require('../../models/User')

// @route       GET api/auth
// @desc        auth
// @access      Public
router.get('/', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password')
    res.status(200).json({ status: 'success', data: user })
  } catch (err) {
    console.error(err.message)
    res.status(500).send('Server Error')
  }
})

// @route       POST api/auth
// @desc        Authenticate user & get token
// @access      Public
router.post(
  '/',
  [
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password is required').exists(),
  ],
  async (req, res) => {
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
      return res.status(400).json({ status: 'fail', errors: errors.array() })
    }

    const { email, password } = req.body

    try {
      // See if user exists
      let user = await User.findOne({ email })

      if (!user) {
        return res
          .status(400)
          .json({ status: 'fail', errors: [{ msg: 'Email doesn not exist' }] })
      }

      // Compare & match password
      const isMatch = await bcrypt.compare(password, user.password)
      if (!isMatch) {
        return res
          .status(400)
          .json({ status: 'fail', errors: [{ msg: 'Incorrect Password' }] })
      }

      // Return jsonwebtoken
      const payload = {
        user: { id: user.id },
      }

      jwt.sign(
        payload,
        config.get('jwtSecret'),
        { expiresIn: 3600 },
        (err, token) => {
          if (err) throw err
          res.status(200).json({ status: 'success', data: user, token })
        }
      )

      // res.status(200).json({ status: 'User Registered', data: user })
    } catch (err) {
      console.error(err.message)
      res.status(500).send('Server Error')
    }
  }
)

module.exports = router
