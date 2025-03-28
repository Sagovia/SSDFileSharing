/*
This will be the MongoDB database model for the Users

Contains:
- Email (for resetting password)
- Username
- Password (Hashed)
- Array of Files they own // TODO
- List of Folders they own // TODO

TODO: Consider ability to change things like -
*/

const mongoose = require('mongoose');
const { schema } = require('./File');
const Schema = mongoose.Schema;

const userSchema = new Schema({
    email: {
        type: Schema.Types.String, //TODO add validation check that email makes actual sense
        required: true,
        unique: true,
    },
    username: {
        type: Schema.Types.String, //TODO add validation check that no spaces or weird characters allowed
        required: true,
        unique: true,
    },
    password: {
        type: Schema.Types.String, //TODO add validation check that no spaces or weird characters allowed
        required: true,
    }
});

const User = mongoose.model("User", userSchema); // Export to Mongoose/mongoDB

module.exports = User; // Export for local use