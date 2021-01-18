const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const User = require('./models/user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET =
  'JDFNBK@$$!#@!&(*)()932wuv8wu8vuwe98u(@&!^!&g8uw38u893wu32h328vuwipu39uf93fjioew';

mongoose.connect('mongodb://localhost:27017/login-app-db', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true,
});
const app = express();

app.use('/', express.static(path.join(__dirname + '/public')));
app.use(bodyParser.json());

// 1.Client proves itself somehow on the request. The session data is in the payload. no state is stored (JWT)
// 2.Client-Server share a secret (Cookie). session data is stored in cache

app.post('/api/change-password', async (req, res) => {
  const { token, newPassword: plainTextPassword } = req.body;

  if (!plainTextPassword || typeof plainTextPassword !== 'string') {
    return res.json({ status: 'error', error: 'Invalid p    assword' });
  }
  if (plainTextPassword.length < 5) {
    return res.json({
      status: 'error',
      error: 'Password too small. Should be at least 6 characters',
    });
  }

  try {
    const user = jwt.verify(token, JWT_SECRET);
    const _id = user.id;
    const password = await bcrypt.hash(plainTextPassword, 10);
    await User.updateOne(
      { _id },
      {
        $set: { password: password },
      }
    );

    res.json({ status: 'ok' });
  } catch (error) {
    return res.json({ status: 'error', error: ';))' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username }).lean();

  if (!user) {
    return res.json({ status: 'error', error: 'Invalid username/password' });
  }

  if (await bcrypt.compare(password, user.password)) {
    // the username,pass combo is successful
    const token = jwt.sign(
      { id: user._id, username: user.username },
      JWT_SECRET
    ); // visible publicly

    return res.json({ status: 'ok', data: token });
  }

  res.json({ status: 'error', error: 'Invalid username/password' });
});

app.post('/api/register', async (req, res) => {
  const { username, password: plainTextPassword } = req.body;

  if (!username || typeof username !== 'string') {
    return res.json({ status: 'error', error: 'Invalid username' });
  }
  if (!plainTextPassword || typeof plainTextPassword !== 'string') {
    return res.json({ status: 'error', error: 'Invalid p    assword' });
  }
  if (plainTextPassword.length < 5) {
    return res.json({
      status: 'error',
      error: 'Password too small. Should be at least 6 characters',
    });
  }

  const password = await bcrypt.hash(plainTextPassword, 10);

  try {
    const response = await User.create({
      username,
      password,
    });
    console.log('user created successfully', response);
  } catch (error) {
    if (error.code === 11000) {
      // duplicate key
      return res.json({ status: 'error', error: 'Username already in use' });
    }
    throw error;
  }

  res.json({ status: 'ok' });
});

app.listen(3333, () => {
  console.log('http://localhost:3333');
});
