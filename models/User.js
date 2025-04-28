/*
This will be the MongoDB database model for the Users

Contains:
- Email (for resetting password)
- Username
- Password (Hashed)
- Array of Files they own // TODO
- List of Folders they own // TODO

*/

const mongoose = require('mongoose');
const { schema } = require('./File');
const Schema = mongoose.Schema;

const userSchema = new Schema({
    email: {
        type: Schema.Types.String, 
        required: true,
        unique: true,
    },
    username: {
        type: Schema.Types.String, 
        required: true,
        unique: true,
    },
    password: {
        type: Schema.Types.String, 
        required: true,
    }
});

const User = mongoose.model("User", userSchema); // Export to Mongoose/mongoDB

module.exports = User; // Export for local use