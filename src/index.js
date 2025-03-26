// Current setup: Files will be saved at /uploads, while file -
// -metadata(including the path, name of file, password (optional) and number of downloads) will be stored in MongoDB database

// Import modules
const express = require("express");
const multer = require('multer');
const mongoose = require("mongoose");
const File = require("../models/File.js");
const bcrypt = require("bcrypt");

// Middleware
// Multer processes files in the multipart/form-data format.
const upload = multer({dest: "uploads"})


mongoose
    .connect("mongodb://localhost/fileDatabase")
    .then(() => console.log('Connected to database'))
    .catch((err) => console.log(`Error: ${err}`));


// Constants
const PORT = 3000;

const app = express();

// Set up EJS as the view engine, must use before response.render() will work
app.set("view engine", "ejs");

app.use(express.urlencoded({extended: true }));




// Pages
app.get("/",
    (request, response) => {
        // Will look for view template called index, usually in folder "views"
        response.render("index"); 
    }
)


// Used for uploading files
app.post("/upload",
    upload.single("file"),
    async (request, response) => {
        const inputFile = {
            // Use multer's file added to request for this
            pathToFile: request.file.path,
            name: request.file.originalname,
        }

        if(request.body.password != null && request.body.password != "") { // If password exists, replace later with proper validation checks
             inputFile.password = bcrypt.hashSync(request.body.password, 10); // Create helper function later
        }

        // Add metadata entry to Mongo database
        const newFile = new File(inputFile);
        await newFile.save();
        
        console.log("Created file:")
        console.log(newFile);

        // Return back to /index, and send the link to the file back:
        response.render("index", {fileLink : `${request.headers.origin}/file/${newFile.id}`});
})


// Used for attempting to download a file with a given id
app.get("/file/:id", // TODO need to consider permissions, if the file id even exists, etc.
    async (request, response) => {
        // Will try to find file of model File in the database
        console.log("before");

        // This is our file metadata MongoDB entry
        const requestedFile = await File.findById(request.params.id);
        console.log("after");

        // Check if has password
        if(requestedFile.password != null) {
            if(request.body.password == null) {
                return response.status(403).render("password"); // redirect back to password page, need to create view for it (done)
            }
        }

        // Check if file was found
        if (!requestedFile) {
            console.log(`File with ID ${request.params.id} not found.`);
            return response.status(404).send("File not found.");
        }

        console.log("Requested file:", requestedFile);



        // Now check to see if password is valid or not: (original, hashed)
        if(requestedFile.password != null) { 
            if(!bcrypt.compareSync(request.body.password, requestedFile.password)) {
                // If wrong password, redirect back to password entering screen
                return response.render("password", {error: true});
            }
        }


        // Update downloadCount
        requestedFile.downloadCount++;
        await requestedFile.save();



        // Download file for user
        response.download(requestedFile.pathToFile, requestedFile.name);
    }
)


// Used for inputting password if a file is password-protected (POST will hide password in body)
app.post("/file/:id", // TODO need to consider permissions, if the file id even exists, etc.
    async (request, response) => {
        // Will try to find file of model File in the database
        console.log("before");

        // This is our file metadata MongoDB entry
        const requestedFile = await File.findById(request.params.id);
        console.log("after");

        // Check if has password
        if(requestedFile.password != null) {
            if(request.body.password == null) {
                return response.status(403).render("password"); // redirect back to password page, need to create view for it (done)
            }
        }

        // Check if file was found
        if (!requestedFile) {
            console.log(`File with ID ${request.params.id} not found.`);
            return response.status(404).send("File not found.");
        }

        console.log("Requested file:", requestedFile);



        // Now check to see if password is valid or not: (original, hashed)
        if(requestedFile.password != null) {
            if(!bcrypt.compareSync(request.body.password, requestedFile.password)) {
                // If wrong password, redirect back to password entering screen
                return response.render("password", {error: true});
            }
        }
    


        // Update downloadCount
        requestedFile.downloadCount++;
        await requestedFile.save();



        // Download file for user
        response.download(requestedFile.pathToFile, requestedFile.name);
    }
)









// Starts up server by listening on a port for HTTP requests
app.listen(PORT, () => {
    // Here you can have something occur when the server starts up
    console.log(`Running on 3000`)
}); 

