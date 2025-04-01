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
        // Not required, owner can be null if file is uploaded by user with no account
    },
    viewWhitelist: [{ 
        type: Schema.Types.ObjectId, 
        ref: 'User' 
    }],
    parentFolder: { // null if no parent folder
        type: Schema.Types.ObjectId, 
        ref: 'Folder' 
    }
    /*
    TODO: Will need to add other related info here, description maybe, upload date etc.
    */
})



const File = mongoose.model("File", fileSchema);

module.exports = File;

