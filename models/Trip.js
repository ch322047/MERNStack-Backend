const mongoose = require('mongoose')

const flightSchema = new mongoose.Schema({
  airline:      { type: String },
  flightNumber: { type: String },
  departure:    { type: Date },
  arrival:      { type: Date },
  booked:       { type: Boolean, default: false }
})

const hotelSchema = new mongoose.Schema({
  name:     { type: String },
  checkIn:  { type: Date },
  checkOut: { type: Date },
  booked:   { type: Boolean, default: false }
})

const activitySchema = new mongoose.Schema({
  name:     { type: String },
  time:     { type: String },
  location: { type: String }
})

const itineraryDaySchema = new mongoose.Schema({
  date:       { type: Date },
  activities: [activitySchema]
})

const packingItemSchema = new mongoose.Schema({
  item:   { type: String },
  packed: { type: Boolean, default: false }
})

const tripSchema = new mongoose.Schema({
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name:        { type: String, required: true },
  destination: { type: String, required: true },
  startDate:   { type: Date, required: true },
  endDate:     { type: Date },
  status:      { type: String, enum: ['planning', 'ready', 'active', 'completed'], default: 'planning' },
  flights:     [flightSchema],
  hotels:      [hotelSchema],
  itinerary:   [itineraryDaySchema],
  packingList: [packingItemSchema]
}, { timestamps: true })

module.exports = mongoose.model('Trip', tripSchema)
