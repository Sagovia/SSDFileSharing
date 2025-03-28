// Current setup: Files will be saved at /uploads, while file -
// -metadata(including the path, name of file, password (optional) and number of downloads) will be stored in MongoDB database

// Import modules
const express = require("express");
const multer = require('multer');
const mongoose = require("mongoose");
const File = require("../models/File.js");
const bcrypt = require("bcrypt");
const session = require('express-session'); // Import to use use sessions
const cookieParser = require('cookie-parser'); // Import to parse cookies (like session cookies)
// Multer processes files in the multipart/form-data format. (middleware)
const passport = require("passport"); // TODO: Remember to download + implement TOTP MFA Passport strategy later
const upload = multer({dest: "uploads"})
require("../strategies/local-strategy.js"); // Import our local strategy for Passport.js authentication
const User = require('../models/User.js'); // Import our mongoose User object
const MongoStore = require("connect-mongo"); // Import connect-mongo for creating a persistent session store



mongoose
    .connect("mongodb://localhost/fileDatabase")
    .then(() => console.log('Connected to database'))
    .catch((err) => console.log(`Error: ${err}`));


// Constants
const PORT = 3000;

const app = express();

// Set up EJS as the view engine, must use before response.render() will work
app.set("view engine", "ejs");

// Global middleware

// Middleware to parse content-type json bodies in request, allows request.body to be defined
app.use(express.json());
app.use(express.urlencoded({extended: true })); 
app.use(cookieParser("session cookie secret value")) // cookieParser must use same secret value as session
app.use(session({ // Set up sessions TODO: Create MongoDB session store to keep users signed in even after server restarts
    secret: "session cookie secret value", // TODO: Maybe generate this dynamically? Unsure what is most secure
    saveUninitialized: false,
    resave: false,
    cookie: {
        maxAge: 60000 * 60 // Session cookies expire after 1 hour TODO: Maybe make longer?
    },
    store: MongoStore.create({ // For creating the persistent session store
        client: mongoose.connection.getClient()
    })
}));
app.use(passport.initialize());
app.use(passport.session()); //




// Pages
app.get("/", // Home page
    (request, response) => {
        // Will look for view template called index, usually in folder "views"
        // By default, it will be sent to upload screen, let's change
        response.render("home");  // TODO: add basic home screen, with login/register button
    }
)


// Page used for uploading files

/* TODO:
- Add middleware for input validation (Multer has built-in file valiation tools via modifying "upload" var, should use these)
- Add middlware for generating + verifying user sessions via express sessions (Access data via request.session)
- Add middleware for authenticating user via Passport.js, request.user != null if successful + logged in

*/
// Should be presented with option to do basic upload (no account required) or precise upload (account required)
/*
Input:  {
    file (required), 
}
*/





// For registering for an account. If user is already logged in, will just redirect to /acc
// TODO: Still need to integrate session middleware into this
app.post("/register",
    async (request, response) => {
        const data = request.body; // TODO: For now assume data is accurate, later add input validation
        console.log(request.body);
        const newUser = new User(data);

        try {
            const savedUser = await newUser.save();
            return response.redirect("/login"); // Successful registering, go to login page
        }
        catch(err) {
            console.log(err);
            return response.sendStatus(401);
        }
    }
)

app.get("/register",
    (request, response) => {
        console.log(request.session.user);
        if(request.user) {
            response.redirect("/acc"); // If user is already logged in, will just redirect to /acc
        }
        else {
            response.render("registerPage"); // Display register page
        }
    }
)



// For logging in. If user is already logged in, will just redirect to /acc
// Input: Username, password
// Output: Error message upon failure, redirect to /acc if successful, possibly alongside info like username
app.post("/login",
    passport.authenticate("local"), 
    (request, response) => {
        if(request.user == null) {
            // Return back to /index, and send the link to the file back:
            // TODO: Make error message more specific, can do via passing message object in done() in strategy definition
            response.render("loginPage", {msg : `Invalid credentials, please try again.`});
        }

        response.render("accountHome"); // TODO: Add account home
    }
)


app.get("/login",
    (request, response) => {
        if(request.user) {
            response.redirect("/acc"); // If user is already logged in, will just redirect to /acc
        }
        else {
            response.render("loginPage"); // Display register page
        }
    }
)




// For logging out. If user is already logged out, will just redirect to /
// Input: Nothing
// Output: Success message upon logging out, or just redirecting to / if already logged out
app.post("/logout",
    (request, response) => {

    }
)


// This is specifically for uploading files
// Input: File, isPrivate, user (of course), parentFolder (Optional)
// If isPrivate: Provide: List of whitelisted usernames whitelistView, whitelistAdd

// Output: Will provide a link to access file, will return via ejs
// TODO: Make sure to verify parentFolder is actually valid and allows to be added to
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



// Home page for logged in users, will display options (create new folder, upload new file), view user's current folders and uploaded files
// Output array of files belonging to user, array of folders belonging to user
app.post("/acc/home",
    upload.single("file"),
    (request, response) => {

    }
)



// Specifically for logged in users, will attempt to view the folder of the given folder ID
// Input: Folder id
// Output: If folder exists + correct permissions, will return array of files that belong in the folder
app.get("/acc/folder/:id",
    (request, response) => {

    }
)


// This is for logged in users who want to create a folder
// Input: folderName, isPrivate, user (of course)
// If isPrivate: Provide: List of whitelisted usernames whitelistView, whitelistAdd
// Output: Success message, or reason for failure
app.post("/acc/createFolder",
    upload.single("file"),
    (request, response) => {

    }
)

// Specifically for logged in users, will attempt to delete the file (assuming they own it + it exists)
// Input: fileName
// Output: Success or failure + error message
// TODO: Be very careful with how you decide what they can delete, make sure that they can't input a file path to somewhere else
app.post("/acc/file/delete",
    (request, response) => {

    }
)



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

