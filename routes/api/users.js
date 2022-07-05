// register user
const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');
const User = require('../../models/User');

// @route   - POST api/users - req type and the end points
// @ access - public
router.post(
  '/',
  [
    check('name', 'Name is required').not().isEmpty(),

    check('email', 'Please input valid email').isEmail(),

    check(
      'password',
      'Please enter a password with 6 or more characters'
    ).isLength({ min: 6 }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      // if the required credentials are not given
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;

    try {
      // see if the user exists
      let user = await User.findOne({ email });

      if (user) {
        // if user already exists
        return res
          .status(400)
          .json({ errors: [{ msg: 'user already exist' }] });
      }

      // get users gravatar
      const avatar = gravatar.url(email, {
        // gives back an image url
        s: '200', // size of the pic
        r: 'pg', // rating
        d: 'mm', // default - if the user doesn't have a profile pic then there should be something
      });

      // storing in database
      user = new User({
        name,
        email,
        avatar,
        password,
      });

      // encrypt the passwords
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(password, salt);
      await user.save(); // saving in the database;

      // return jsonwebtoken
      const payload = {
        user: {
          id: user.id,
        },
      };

      jwt.sign(
        payload,
        config.get('jwtToken'),
        { expiresIn: 360000 },
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).send('server error');
    }
  }
);

module.exports = router;
