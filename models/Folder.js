/*
This will store collaborative folder info and related metadata


Will hold:
- List of files present in the folder
- Folder name x
- Owner of the folder x
- Folder creation date
- If folder is public (IE can be viewed by anyone) x
- Whitelisted users who are allowed to view the folder x
- Whitelisted users who are allowed to add to the folder (Add files) x
- Whitelisted users who are allowed to delete from the folder (Remove files) x

If folder is private, then it should also contain:
- Whitelisted users who are allowed to view the folder


*/

const mongoose = require('mongoose');
const { schema } = require('./File');
const Schema = mongoose.Schema;

const folderSchema = new Schema({
    name: {
        type: Schema.Types.String, 
        required: true
    },
    password: {
        type: Schema.Types.String, 
    },
    owner: { // This will reference the _id of the owner, must be a User 
        type: Schema.Types.ObjectId,
        ref: 'User', // Refers to the User model 
        required: true // Folder must have an owner 
    },
    isPrivate: {
        type: Schema.Types.Boolean,
        required: true
    },
    editWhitelist: [{ 
        type: Schema.Types.ObjectId, 
        ref: 'User' 
    }],
    viewWhitelist: [{ 
        type: Schema.Types.ObjectId, 
        ref: 'User' 
    }],
    deleteWhitelist: [{ 
        type: Schema.Types.ObjectId, 
        ref: 'User' 
    }],
    filesContained: [{ 
        type: Schema.Types.ObjectId, 
        ref: 'File',
        required: true 
    }],
});


const Folder = mongoose.model("Folder", folderSchema); // Export to Mongoose/mongoDB

module.exports = Folder; // Export for local use