const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');

const User = require('../../models/User');

// @route   POST api/users
// @desc    Register user
// @access  Public
router.post(
	'/',
	[
		check('name', 'Name is required')
			.not()
			.isEmpty(),
		check('email', 'Please include a valid email').isEmail(),
		check(
			'password',
			'please enter a password with 6 or more characters'
		).isLength({ min: 6 })
	],
	async (req, res) => {
		const errors = validationResult(req);

		if (!errors.isEmpty()) {
			return res.status(400).json({ errors: errors.array() });
		}

		const { name, email, password } = req.body;

		try {
			// See if user exists
			let user = await User.findOne({ email });
			if (user) {
				return res
					.status(400)
					.json({ errors: [{ msg: 'User already exists' }] });
			}

			// Get users gravatar and add to users's object
			const avatar = `https:${gravatar.url(email, {
				s: '200',
				r: 'pg',
				d: 'mm'
			})}`;
			/*
			NPM Gravatar Module Base URL Issue:
			https://github.com/emerleite/node-gravatar/issues/47
			
			var baseURL,fix leading "//"" to instead be "https://"" when gravatar
			url is created via gravatar.url(email) the url is generated as:

							 "//www.gravatar.com"
							 
			when should be:

							"https://www.gravatar.com"

			If this issue gets fixed in latter versions, turn the code back the
			orginal bellow:

						const avatar = gravatar.url(email, {
							s: '200',
							r: 'pg',
							d: 'mm'
						});

			Check MongoDB if any gravatar URL was saved in wrong format.
			*/

			user = new User({
				name,
				email,
				avatar,
				password
			});

			// Encript password before registering the new user
			const salt = await bcrypt.genSalt(10);
			user.password = await bcrypt.hash(password, salt);
			await user.save();

			// Return jsonwebtoken
			const payload = {
				user: {
					id: user.id
				}
			};
			jwt.sign(
				payload,
				config.get('jwtSecret'),
				{ expiresIn: 360000 },
				(err, token) => {
					if (err) throw err;
					res.json({ token });
				}
			);
		} catch (err) {
			console.error(err.message);
			res.status(500).send('Server error');
		}
	}
);

module.exports = router;
