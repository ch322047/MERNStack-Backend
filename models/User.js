const mongoose = require('mongoose')

const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName:  { type: String, required: true },

  login: {
    type: String,
    unique: true,
    required: true,
    trim: true,
  },

  email: {
    type: String,
    lowercase: true,
    required: true,
    trim: true,
  },

  passwordHash: {
    type: String,
    required: true,
  },

  isVerified: {
    type: Boolean,
    default: false,
  },

  verifyTokenHash: String,
  verifyTokenExpiresAt: Date,

  resetTokenHash: String,
  resetTokenExpiresAt: Date,

  loginCodeHash: String,
  loginCodeExpiresAt: Date,
  loginCodeAttempts: {
    type: Number,
    default: 0,
  },

}, { timestamps: true })

module.exports = mongoose.model('User', userSchema)
