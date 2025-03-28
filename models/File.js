// This will be the MongoDB model for our files
// Not storing the file data itself

// TODO: Add other metadata, like date added

const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const fileSchema = new Schema({
    pathToFile: {
        type: Schema.Types.String,
        required: true,
        unique: true
    },
    name: {
        type: Schema.Types.String,
        required: true,
    },
    password: {
        type: Schema.Types.String
    },
    downloadCount: {
        type: Schema.Types.Number,
        required: true,
        default: 0 // By default, the file has been downloaded 0 times
    },
    // User who uploaded the File will be considered the owner
    owner: { // This will reference the _id of the owner, must be a User TODO: Figure out validation checking for this later
        type: Schema.Types.ObjectId,
        ref: 'User', // Refers to the User model
        required: true
    }
    /*
    TODO: Will need to add other related info here, like whitelisted users that can access the file, description maybe, upload date etc.
    */
})



const File = mongoose.model("File", fileSchema);

module.exports = File;

