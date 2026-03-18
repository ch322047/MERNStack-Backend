const express = require('express');
const cors = require('cors');
const PORT = process.env.PORT || 5001;

const mongoose = require('mongoose');
require('dotenv').config();

const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const User = require('./models/User');

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error("MongoDB connection error:", err));

//mail transporter
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

const app = express();
app.use(cors());
// app.use(bodyParser.json());
app.use(express.json());

//helper fubctions
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

//register endpoint
app.post('/api/register', async (req, res) => {
  try {
    const { firstName, lastName, login, email, password } = req.body;

    //check if all fields are filled
    if (!firstName || !lastName || !login || !email || !password) {
      return res.status(400).json({ error: 'Please fill out all fields' });
    }

    const trimmedLogin = login.trim();
    const normalizedEmail = email.trim().toLowerCase();

    //check if login exitsts
    const existingLogin = await User.findOne({ login: trimmedLogin });
    if (existingLogin) {
      return res.status(400).json({ error: 'This Login exists already' });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const verifyToken = generateToken();
    const verifyTokenHash = hashToken(verifyToken);
    const verifyTokenExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

    const user = await User.create({
      firstName: firstName.trim(),
      lastName: lastName.trim(),
      login: trimmedLogin,
      email: normalizedEmail,
      passwordHash,
      isVerified: false,
      verifyTokenHash,
      verifyTokenExpiresAt,
    });

    const verifyUrl = `http://localhost:5001/api/verify-email?token=${verifyToken}`;

    await transporter.sendMail({
      from: process.env.MAIL_FROM,
      to: user.email,
      subject: 'Verify your email',
      html: `
        <p>Hi ${user.firstName},</p>
        <p>Welcome to MiCon.</p>
        <p>Please verify your email with this link:</p>
        <a href="${verifyUrl}">${verifyUrl}</a>
        <p>Link expires in 24 hours.</p>
      `,
    });

    //success
    return res.status(201).json({
      message: 'Registration successful. You will need to verify your email before logging in.',
      error: '',
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/addcard', async (req, res, next) =>
{
  // incoming: userId, color
  // outgoing: error
	
  const { userId, card } = req.body;

  const newCard = {Card:card,UserId:userId};
  var error = '';

  try
  {
    const db = client.db('MainDatabase');
    const result = db.collection('Cards').insertOne(newCard);
  }
  catch(e)
  {
    error = e.toString();
  }

  var ret = { error: error };
  res.status(200).json(ret);
});

app.post('/api/searchcards', async (req, res, next) => 
{
  // incoming: userId, search
  // outgoing: results[], error

  var error = '';

  const { userId, search } = req.body;

  var _search = search.trim();
  
  const db = client.db('MainDatabase');
  const results = await db.collection('Cards').find({"Card":{$regex:_search+'.*', $options:'i'}}).toArray();
  
  var _ret = [];
  for( var i=0; i<results.length; i++ )
  {
    _ret.push( results[i].Card );
  }
  
  var ret = {results:_ret, error:error};
  res.status(200).json(ret);
});

app.post('/api/login', async (req, res, next) => 
{
  // incoming: login, password
  // outgoing: id, firstName, lastName, error
	
 var error = '';

  const { login, password } = req.body;

  const db = client.db('MainDatabase');
  const results = await db.collection('Users').find({Login:login,Password:password}).toArray();

  var id = -1;
  var fn = '';
  var ln = '';

  if( results.length > 0 )
  {
    id = results[0].UserID;
    fn = results[0].FirstName;
    ln = results[0].LastName;
  }

  var ret = { id:id, firstName:fn, lastName:ln, error:''};
  res.status(200).json(ret);
});



app.use((req, res, next) => 
{

  app.get("/api/ping", (req, res, next) => {
	res.status(200).json({ message: "Hello World" });
  });
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Origin, X-Requested-With, Content-Type, Accept, Authorization'
  );
  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET, POST, PATCH, DELETE, OPTIONS'
  );
  next();
});

//verify email
app.get('/api/verify-email', async (req, res) => {
  try {
    const { token } = req.query;

    //missing token
    if (!token) {
      return res.status(400).json({ error: 'Token is missing' });
    }

    const tokenHash = hashToken(token);

    const user = await User.findOne({
      verifyTokenHash: tokenHash,
      verifyTokenExpiresAt: { $gt: new Date() },
    });

    //invalid token
    if (!user) {
      return res.status(400).json({ error: 'Token in invalid or expired' });
    }

    user.isVerified = true;
    user.verifyTokenHash = null;
    user.verifyTokenExpiresAt = null;

    await user.save();

    //success
    return res.status(200).json({
      message: 'Email successfully verified',
      error: '',
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.listen(PORT,() => {
  console.log(`Server running on port ${PORT}`);
}); // start Node + Express server on port 5001
