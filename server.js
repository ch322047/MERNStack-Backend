/*AI Assistance Disclosure

This project was developed with assistance from generative AI tools:

- **Tool**: ChatGPT-5.3
- **Dates**: March 15-21, 2026
- **Scope**: Help with implementing register/login and security features
- **Use**: Explanations for implementation of API endpoints for login and register with 
  email verification, 2FA and password reset

All AI-generated code was reviewed, tested, and modified to meet 
assignment requirements. Final implementation reflects our understanding 
of the concepts.*/

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const PORT = process.env.PORT || 5001;

const mongoose = require('mongoose');

const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const User = require('./models/User');
const Trip = require('./models/Trip');

const jwt = require('jsonwebtoken');
const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SMTP_PASS);

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
  connectionTimeout: 10000,
  greetingTimeout: 10000,
  socketTimeout: 10000,
});

//testing
transporter.verify()
  .then(() => console.log('SMTP ready'))
  .catch(err => console.error('SMTP error:', err));

const app = express();
app.use(cors());
// app.use(bodyParser.json());
app.use(express.json());

//helper functions register/ email verification
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

//helper functions login
function generateLoginCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function signJwt(user) {
  return jwt.sign(
    {
      sub: user._id.toString(),
      login: user.login,
      email: user.email,
    },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
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

    const verifyUrl = `https://lampstackprojectgroup9.com/api/verify-email?token=${verifyToken}`;

    await sgMail.send({
      to: user.email,
      from: process.env.MAIL_FROM,
      subject: 'Verify your email',
      html: `
        <p>Hi ${user.firstName},</p>
        <p>Please verify your email by clicking this link:</p>
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

//login
app.post('/api/login', async (req, res) => {
  try {
    const { login, password } = req.body;

    //input validation
    if (!login || !password) {
      return res.status(400).json({ error: 'Fill out all fields' });
    }

    const trimmedLogin = login.trim();

    const user = await User.findOne({ login: trimmedLogin });

    if (!user) {
      return res.status(401).json({ error: 'Invalid user' });
    }

    const passwordMatch = await bcrypt.compare(password, user.passwordHash);

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    if (!user.isVerified) {
      return res.status(403).json({ error: 'Your email is not verified yet' });
    }

    const loginCode = generateLoginCode();
    const loginCodeHash = hashToken(loginCode);
    const loginCodeExpiresAt = new Date(Date.now() + 30 * 60 * 1000);

    user.loginCodeHash = loginCodeHash;
    user.loginCodeExpiresAt = loginCodeExpiresAt;
    user.loginCodeAttempts = 0;

    await user.save();

    //send email with login code
    await sgMail.send({
      to: user.email,
      from: process.env.MAIL_FROM,
      subject: 'Your login verification code',
      html: `
        <p>Hi ${user.firstName},</p>
        <p>Your login verification code is:</p>
        <h2>${loginCode}</h2>
        <p>Code expires in 30 minutes.</p>
      `,
    });

    return res.status(200).json({
      message: 'Login code sent to email',
      error: '',
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
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

//verify login code
app.post('/api/verify-login-code', async (req, res) => {
  try {
    const { login, code } = req.body;

    if (!login || !code) {
      return res.status(400).json({ error: 'Login and code are required' });
    }

    const trimmedLogin = login.trim();

    const user = await User.findOne({ login: trimmedLogin });

    //check if valid code
    if (!user) {
      return res.status(400).json({ error: 'Code is invalid or expired' });
    }

    if (!user.loginCodeHash || !user.loginCodeExpiresAt) {
      return res.status(400).json({ error: 'No active login code' });
    }

    if (user.loginCodeExpiresAt < new Date()) {
      user.loginCodeHash = null;
      user.loginCodeExpiresAt = null;
      user.loginCodeAttempts = 0;
      await user.save();

      return res.status(400).json({ error: 'Invalid or expired code' });
    }

    if (user.loginCodeAttempts >= 5) {
      return res.status(429).json({ error: 'Too many incorrect login attempts' });
    }

    const incomingCodeHash = hashToken(code);

    if (incomingCodeHash !== user.loginCodeHash) {
      user.loginCodeAttempts += 1;
      await user.save();

      return res.status(400).json({ error: 'Invalid or expired code' });
    }

    user.loginCodeHash = null;
    user.loginCodeExpiresAt = null;
    user.loginCodeAttempts = 0;
    await user.save();

    const token = signJwt(user);

    return res.status(200).json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        login: user.login,
        email: user.email,
      },
      error: '',
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
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

//forgot password
app.post('/api/forgot-password', async (req, res) => {
  try {
    const { login, email } = req.body;

    if (!login || !email) {
      return res.status(400).json({ error: 'Login and email are required' });
    }

    const trimmedLogin = login.trim();
    const normalizedEmail = email.trim().toLowerCase();

    const user = await User.findOne({
      login: trimmedLogin,
      email: normalizedEmail
    });

    if (!user) {
      return res.status(200).json({
        message: 'If an account exists, a password reset email has been sent.',
        error: '',
      });
    }

    const resetToken = generateToken();
    const resetTokenHash = hashToken(resetToken);
    const resetTokenExpiresAt = new Date(Date.now() + 30 * 60 * 1000);

    user.resetTokenHash = resetTokenHash;
    user.resetTokenExpiresAt = resetTokenExpiresAt;
    await user.save();

    const resetUrl = `https://lampstackprojectgroup9.com/api/reset-password?token=${resetToken}`;

    await sgMail.send({
      to: user.email,
      from: process.env.MAIL_FROM,
      subject: 'Reset your password',
      html: `
        <p>Hi ${user.firstName},</p>
        <p>Please click the link below to reset your password:</p>
        <a href="${resetUrl}">${resetUrl}</a>
        <p>Link expires in 30 minutes.</p>
      `,
    });

    return res.status(200).json({
      message: 'If an account exists, a password reset email has been sent.',
      error: '',
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

//reset password
app.post('/api/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({ error: 'Token and new password are required' });
    }

    const tokenHash = hashToken(token);

    const user = await User.findOne({
      resetTokenHash: tokenHash,
      resetTokenExpiresAt: { $gt: new Date() },
    });

    if (!user) {
      return res.status(400).json({ error: 'This token is invalid or expired' });
    }

    user.passwordHash = await bcrypt.hash(newPassword, 12);
    user.resetTokenHash = null;
    user.resetTokenExpiresAt = null;

    await user.save();

    return res.status(200).json({
      message: 'Password reset was successful',
      error: '',
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Search for trip by id and send result to frontend
app.get('/api/get-trip/:tripId', async(req, res) => {
  try {
    // Save what the frontend sent
    const {tripId} = req.params;

    // Lookup document
    const trip = await Trip.findById(tripId);

    // Make sure tripId exists
    if(!trip) {
      return res.status(400).json({error: 'trip does not exist'});
    }

    // Return success message and trip
    return res.status(200).json({
      message: 'successfully found the trip',
      trip: trip,
      error: ''
    });
  } catch(err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Create a trip
app.post('/api/create-trip/:userId', async(req, res) => {
  try {
    // Save what the frontend sent
    const {userId} = req.params;
    const {name, destination, startDate, endDate, status} = req.body;

    // Check that all required fields are present
    if(!userId || !name || !destination || !startDate) {
      return res.status(400).json({error: 'userId, name, destination, and startDate are required'});
    }

    // Make sure userId exists
    const theUserExists = await User.findById(userId);

    if(!theUserExists) {
      return res.status(400).json({error: 'userId does not exist'});
    }

    // Create new trip
    const newTrip = await Trip.create({
      userId,
      name,
      destination,
      startDate,
      endDate,
      status
    });

    // Return success message and tripId
    return res.status(200).json({
      message: 'successfully created a trip',
      tripId: newTrip._id,
      error: ''
    });
  } catch(err) {
    console.error(err);
    return res.status(500).json({error: 'Server error'});
  }
});

// Add a flight
app.post('/api/add-flight/:userId/:tripId', async(req, res) => {
  try {
    // Save what the frontend sent
    const {userId, tripId} = req.params;
    const {airline, flightNumber, departure, arrival, booked} = req.body;

    // Make sure userId exists
    const user = await User.findById(userId);

    if(!user) {
      return res.status(400).json({error: 'userId does not exist'});
    }

    // Make sure tripId exists
    const trip = await Trip.findById(tripId);

    if(!trip) {
      return res.status(400).json({error: 'tripId does not exist'});
    }

    // Push the new flight into the flight array
    trip.flights.push({airline, flightNumber, departure, arrival, booked});

    // Save to database
    await trip.save();

    // Return success message
    return res.status(200).json({
      message: 'successfully added a flight',
      error: ''
    });
  } catch(err) {
    console.error(err);
    return res.status(500).json({error: 'Server error'});
  }
});

// Add a hotel
app.post('/api/add-hotel/:userId/:tripId', async(req, res) => {
  try {
    // Save what the frontend sent
    const {userId, tripId} = req.params;
    const {name, checkIn, checkOut, booked} = req.body;

    // Make sure userId exists
    const user = await User.findById(userId);

    if(!user) {
      return res.status(400).json({error: 'userId does not exist'});
    }

    // Make sure tripId exists
    const trip = await Trip.findById(tripId);

    if(!trip) {
      return res.status(400).json({error: 'tripId does not exist'});
    }

    // Push the new hotel into the hotel array
    trip.hotels.push({name, checkIn, checkOut, booked});

    // Save to database
    await trip.save();

    // Return success message
    return res.status(200).json({
      message: 'successfully added a hotel',
      error: ''
    });
  } catch(err) {
    console.error(err);
    return res.status(500).json({error: 'Server error'});
  }
});

// Add a day to the itinerary
app.post('/api/add-itinerary-day/:userId/:tripId', async(req, res) => {
  try {
    // Save what the frontend sent
    const {userId, tripId} = req.params;
    const {date} = req.body;

    // Make sure userId exists
    const user = await User.findById(userId);

    if(!user) {
      return res.status(400).json({error: 'userId does not exist'});
    }

    // Make sure tripId exists
    const trip = await Trip.findById(tripId);

    if(!trip) {
      return res.status(400).json({error: 'tripId does not exist'});
    }

    // Push the new itinerary day into the itinerary array
    trip.itinerary.push({date});

    // Save to database
    await trip.save();

    // Return success message
    return res.status(200).json({
      message: 'successfully added a day to the itinerary',
      error: ''
    });
  } catch(err) {
    console.error(err);
    return res.status(500).json({error: 'Server error'});
  }
});

// Add an activity to an existing day in the itinerary
app.post('/api/add-itinerary-day-activity/:userId/:tripId/:dayId', async(req, res) => {
  try {
    // Save what the frontend sent
    const {userId, tripId, dayId} = req.params;
    const {name, time, location} = req.body;

    // Make sure userId exists
    const user = await User.findById(userId);

    if(!user) {
      return res.status(400).json({error: 'userId does not exist'});
    }

    // Make sure tripId exists
    const trip = await Trip.findById(tripId);

    if(!trip) {
      return res.status(400).json({error: 'tripId does not exist'});
    }

    // Make sure dayId is a day
    const day = trip.itinerary.id(dayId);

    if(!day) {
      return res.status(400).json({error: 'dayId is not a day'});
    }

    // Push the new activity into the activities array
    day.activities.push({name, time, location});

    // Save to database
    await trip.save();

    // Return success message
    return res.status(200).json({
      message: 'successfully added an activity to the requested day in the itinerary',
      error: ''
    });
  } catch(err) {
    console.error(err);
    return res.status(500).json({error: 'Server error'});
  }
});

// Add an item to the packing list
app.post('/api/add-to-packing-list/:userId/:tripId', async(req, res) => {
  try {
    // Save what the frontend sent
    const {userId, tripId} = req.params;
    const {item, packed} = req.body;

    // Make sure userId exists
    const user = await User.findById(userId);

    if(!user) {
      return res.status(400).json({error: 'userId does not exist'});
    }

    // Make sure tripId exists
    const trip = await Trip.findById(tripId);

    if(!trip) {
      return res.status(400).json({error: 'tripId does not exist'});
    }

    // Push the new item into the packingList array
    trip.packingList.push({item, packed});

    // Save to database
    await trip.save();

    // Return success message
    return res.status(200).json({
      message: 'successfully added an item to the packing list',
      error: ''
    });
  } catch(err) {
    console.error(err);
    return res.status(500).json({error: 'Server error'});
  }
});

app.listen(PORT,() => {
  console.log(`Server running on port ${PORT}`);
}); // start Node + Express server on port 5001
