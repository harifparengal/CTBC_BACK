const mongoose = require("mongoose");

const projectScema = new mongoose.Schema({
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
    },
    tag: {
        type: String,
        required:true
    }
});

const Project = mongoose.model("Project", projectScema, 'projects');
module.exports = Project;