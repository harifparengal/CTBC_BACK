const mongoose = require("mongoose");

const blogSchema = new mongoose.Schema({
    description: {
        type: String,
        required: true,
    },
    name: {
        type: String,
        required: true,
    },
    img: {
        type: Buffer,
        required: true,
    }
});

const Blog = mongoose.model("Blog", blogSchema, 'blogs');
module.exports = Blog;