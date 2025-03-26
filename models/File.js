// This will be the MongoDB model for our files
// Not storing the file data itself

// TODO: Add other metadata, like date added, owner of the file

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
    }
    /*
    TODO: Will need to add other related info here, like whitelisted users that can access the file, description maybe, upload date etc.
    */
})



const File = mongoose.model("File", fileSchema);

module.exports = File;

