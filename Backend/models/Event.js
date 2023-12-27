const mongoose = require("mongoose");

const eventSchema = new mongoose.Schema({
    description: {
        type: String,
        required: true,
    },
    amount: {
        type: Number,
        required: true,
    },
    img: {
        type: Buffer,
        required: true,
    },
});

const Event = mongoose.model("Event", eventSchema, 'events');
module.exports = Event;