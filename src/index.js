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
const Folder = require('../models/Folder.js'); // Import our mongoose Folder object
const MongoStore = require("connect-mongo"); // Import connect-mongo for creating a persistent session store
const {query, validationResult, body, matchedData, checkSchema} = require('express-validator'); // Import express-validator



// Import middlewares:
const {validateFile, validateFolder, checkOwnership, checkFolderOwnership, checkWhitelist, checkFolderWhitelist, folderValidationCheck, multerFileValidationCheck, verifyPrivateWhitelist, resolveFiletoParentFolder, resolveFolderIDtoFolder, checkPasswordForFile, checkPasswordForFolder} = require("../utils/middlewares.js");

// Validation schemas
const userValidationSchema = require("../validationSchemas/userValidationSchema.js");
const fileValidationSchema = require("../validationSchemas/fileValidationSchema.js");
const folderValidationScema = require("../validationSchemas/folderValidationSchema.js");


// Import helper functions
const {hashPassword, deleteFile, renderFileView, renderHomepage, deleteFolder} = require('../utils/helpers.js'); 


// TODO: Login session expires even if in use, want it to last longer


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
// Input: Accepts username, password, email
// Output: Errors if invalid input, will redirect to /login upon success
app.post("/register",
    checkSchema(userValidationSchema), // Validation for user register info
    async (request, response) => {
        console.log("Inside POST /register");

        const validationErrors = validationResult(request);
        if(!validationErrors.isEmpty()) { // Errors in input
            console.log("POST /register input invalid");
            return response.status(400).send({errors: validationErrors.array()}); 
        }

        const data = matchedData(request);

        // Hash password
        data.password = hashPassword(data.password);

        const newUser = new User(data);

        try { // Try saving new user to database
            const savedUser = await newUser.save();
            return response.redirect("/login"); // Successful registering, go to login page
        }
        catch(err) {
            console.log(err);
            return response.status(401).send(err);
        }
    }
)

// Will display registerPage if not logged in, redirect to /acc/home otherwise
app.get("/register",
    (request, response) => {
        console.log("Inside GET /register");
        if(request.user) { // If logged in
            response.redirect("/acc/home"); // If user is already logged in, will just redirect to /acc/home
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
        if(request.user == null) { // If login not successful
            // Return back to /index, and send the link to the file back:
            // TODO: Make error message more specific, can do via passing message object in done() in strategy definition
            response.render("loginPage", {msg : `Invalid credentials, please try again.`});
        }

        response.redirect("/acc/home"); 
    }
)


app.get("/login",
    (request, response) => {
        if(request.user) { // If logged in
            return response.redirect("/acc/home"); // If user is already logged in, will just redirect to /acc
        }
        else {
            return response.render("loginPage"); // Display register page
        }
    }
)




// For logging out. If user is already logged out, will just redirect to /
// Input: Nothing
// Output: Success message upon logging out, or just redirecting to / if already logged out
app.post("/logout",
    (request, response) => {
        request.session.destroy(() => {
            response.clearCookie("connect.sid"); // Clear session cookie
            response.redirect("/"); // Redirect to home page
        });
    }
)




// This is specifically for uploading files to your account (Not a folder)
// Input: password, parentFolderID (Optional), isPrivate + viewWhitelistUsernames string (optional)
app.post("/upload",
    upload.single("file"), // Upload file
    checkSchema(fileValidationSchema), // Validate password is valid (if given)
    multerFileValidationCheck, // Will validate uploaded file info + sanitize file name
    resolveFolderIDtoFolder,// Idea: Middleware to attach request.folder for parent folder (if exists)
    checkFolderWhitelist, //  // Adds .canViewFolder .canDeleteFolder .canEditFolder to request based on request.folder
    checkFolderOwnership, // Adds request.isFolderOwner
    verifyPrivateWhitelist, // Checks given whitelist, adds .viewWhitelist to request if everything's valid
    async (request, response) => {
        console.log("Inside POST /upload");

        // upload.single("file")
        const inputFile = {
            // Use multer's file added to request for this
            pathToFile: request.file.path,
            name: request.file.originalname,
            owner: request.user?.id ?? request.user ?? null, // Add owner if user is logged in, null as default to indicate no owner
        }

        const passwordValidationErrors = validationResult(request);

        const data = matchedData(request);
        console.log(data);

        if(data.password != null) {
            if(!passwordValidationErrors.isEmpty()) {
                deleteFile(request.file);
                return response.status(400).send({errors: passwordValidationErrors.array()}); 
            }
            data.password = hashPassword(data.password)
            inputFile.password = data.password;
        }

        inputFile.viewWhitelist = request.viewWhitelist; // Already been validated

        if(request.folder != null) { // Now consider if uploading to a folder
            if(!request.isFolderOwner && !request.canEditFolder) { // Has no permissions to upload to folder
                // FIX NEEDED, TODO remove the file, it's been uploaded already
                return response.status(403).send("No permissions to add to this folder"); 
            }
            // Folder selection valid, update parentFolder for new file
            inputFile.parentFolder = request.folder;
        }

        // Add metadata entry to Mongo database
        const newFile = new File(inputFile);
        await newFile.save();

        // Add new file to desired parent folder, if applicable
        const folder = request.folder;
        if(folder) { // If requested folder exists and allowed to upload to it
            folder.filesContained.push(newFile); // File now added to the folder
            await folder.save();
            console.log(folder);
            console.log("file added to folder");
        }

        console.log("Created file:")
        console.log(newFile);

        // Return back to /index, and send the link to the file back:
        response.render("index", {fileLink : `${request.headers.origin}/file/${newFile.id}`});
})


app.get("/upload", 
    (request, response) => {
        console.log("Inside GET /upload");
        if(request.query.parentFolderID != null) { // If uploading to a folder, pass the parentFolderID for the upload
            const parentFolderID = request.query.parentFolderID;
            console.log("Testing11");
            console.log(parentFolderID);
            return response.render("index", {parentFolderID});
        }
        // Otherwise not needed
        return response.render("index");
    }
)


// Input: File id as route paramter, password (optional), request.user
// Output: Will display file if passed access controls

app.get("/file/view/:id",  // TODO: DO THIS NEXT, also check if parent folder is related or not
    checkSchema(fileValidationSchema), // Validate password is valid (if given)
    validateFile, // attach request.file if exists, returns err if otherwise
    checkOwnership, // attach request.isFileOwner
    checkWhitelist, // attach request.passesFileViewWhitelist
    resolveFiletoParentFolder,// Idea: Middleware to attach request.folder for parent folder (if exists)
    checkFolderWhitelist, //  // Adds .canViewFolder .canDeleteFolder .canEditFolder to request based on request.folder
    checkFolderOwnership, // Adds request.isFolderOwner
    checkPasswordForFile, // Renders password entering page if missing or incorrect
    (request, response) => {
        console.log("Inside GET /file/view/:id");
        console.log(request.isFileOwner);
        console.log(request.isFolderOwner);
        console.log(request.canViewFolder);
        console.log(request.passesFileViewWhitelist);


        if(request.folder) { // If file is in a parent folder
            if(!(request.isFolderOwner || request.canViewFolder)) {
                return response.send("No permissions to view files within the parent folder"); 
            }
            // User allowed to access folder, continue:
            return renderFileView(request, response);
        }


        // Now consider case where there's no parent folder:
        if(request.isFileOwner || request.passesFileViewWhitelist) {
            return renderFileView(request, response);
        }

        // Now check password if nothing else validated the user
        if(request.correctFilePassword) {
            return renderFileView(request, response);
        }
        else {
            console.log("test");
            return response.render("password");
        }

        
        return response.status(403).send("No permissions to view this file."); 
    }
)

// If we need to enter password to view the file details
app.post("/file/view/:id",  // TODO: DO THIS NEXT, also check if parent folder is related or not
    checkSchema(fileValidationSchema), // Validate password is valid (if given)
    validateFile, // attach request.file if exists, returns err if otherwise
    checkOwnership, // attach request.isFileOwner
    checkWhitelist, // attach request.passesFileViewWhitelist
    resolveFiletoParentFolder,// Idea: Middleware to attach request.folder for parent folder (if exists)
    checkFolderWhitelist, //  // Adds .canViewFolder .canDeleteFolder .canEditFolder to request based on request.folder
    checkFolderOwnership, // Adds request.isFolderOwner
    checkPasswordForFile, // Renders password entering page if missing or incorrect
    (request, response) => {
        console.log("Inside GET /file/view/:id");
        console.log(request.isFileOwner);
        console.log(request.isFolderOwner);
        console.log(request.canViewFolder);
        console.log(request.passesFileViewWhitelist);

        if(request.folder) { // If file is in a parent folder
            if(!(request.isFolderOwner || request.canViewFolder)) {
                return response.status(403).send("No permissions to view files within the parent folder"); 
            }
            // User allowed to access folder, continue:
            return renderFileView(request, response);
        }


        // Now consider case where there's no parent folder:
        if(request.isFileOwner || request.passesFileViewWhitelist) {
            return renderFileView(request, response);
        }

        // Now check password if nothing else validated the user
        if(request.correctFilePassword) {
            return renderFileView(request, response);
        }
        else {
            return response.render("password");
        }

        
        return response.status(403).send("No permissions to view this file."); 
    }
)






/*
app.post("/file/view/:id",  
    validateFile, 
    checkOwnership, 
    checkWhitelist, 
    checkPassword,
    (request, response) => {
        // All checks passed, render the file info
        renderFileView(request, response);
    }
)
*/


// Specifically for logged in users, will attempt to delete the file (assuming they own it + it exists)
// Input: fileName
// Output: Success or failure + error message
// TODO: Be very careful with how you decide what they can delete, make sure that they can't input a file path to somewhere else
app.post("/file/delete/:id",
    validateFile, // attach request.file if exists, returns err if otherwise
    checkOwnership, // attach request.isFileOwner
    checkWhitelist, // attach request.canViewFile
    resolveFiletoParentFolder,// Idea: Middleware to attach request.folder for parent folder (if exists)
    checkFolderWhitelist, //  // Adds .canViewFolder .canDeleteFolder .canEditFolder to request based on request.folder
    checkFolderOwnership, // Adds request.isFolderOwner
    checkPasswordForFile, // Will redirect to password screen if password needed but not given or incorrect
    async (request, response) => {
        console.log("Inside POST /file/delete")
        /*
        Logic:
        If (File is in a folder):
            if(folder is public):
                Allow deletion
            else if(User on folder deletion whitelist):
                Allow deletion
        else if(user owns file):
            Allow deletion
        else if(Not logged in):
            Redirect to /login
        else:
            Error, permission denied
        */
        if(request.folder) { // If file is in folder
            if(!request.folder.isPrivate) { // If folder is public
                await deleteFile(request.file);
                return response.redirect("/acc/folder/:" + request.folder.id); // Go to folder view

            }
            if(request.isFolderOwner || request.canDeleteFolder) {
                await deleteFile(request.file);
                return response.redirect("/acc/folder/:" + request.folder.id); // Go to folder view
            }
        }
        else if (request.isFileOwner){
            await deleteFile(request.file);
            return response.redirect("/acc/home"); // Go to account homepage
        }
        else if(request.user == null) { // Not logged in
            return response.redirect("/login");
        }
        else {
            return response.status(400).send("Permission to delete file denied");
        }
    }
)


// Used for attempting to download a file with a given id, no password input
app.get("/file/:id",
    checkSchema(fileValidationSchema), // Validate password is valid (if given)
    validateFile, // attach request.file if exists, returns err if otherwise
    checkOwnership, // attach request.isFileOwner
    checkWhitelist, // attach request.passesFileViewWhitelist
    resolveFiletoParentFolder,// Idea: Middleware to attach request.folder for parent folder (if exists)
    checkFolderWhitelist, //  // Adds .canViewFolder .canDeleteFolder .canEditFolder to request based on request.folder
    checkFolderOwnership, // Adds request.isFolderOwner
    checkPasswordForFile, // Adds request.correctFilePassword
    async (request, response) => {
        console.log("Inside GET /file/:id");

        const requestedFile = request.file;

        if(request.folder) { // If file is in a parent folder
            if(!(request.isFolderOwner || request.canViewFolder)) {
                return response.status(403).send("No permissions to download files within the parent folder"); 
            }
            // User allowed to access folder, continue:
            // Update downloadCount
            requestedFile.downloadCount++;
            await requestedFile.save();
            // Download file for user
            return response.download(requestedFile.pathToFile, requestedFile.name);
        }


        // Now consider case where there's no parent folder:
        if(request.isFileOwner || request.passesFileViewWhitelist) {
            // User allowed to access folder, continue:
            // Update downloadCount
            requestedFile.downloadCount++;
            await requestedFile.save();
            // Download file for user
            return response.download(requestedFile.pathToFile, requestedFile.name);
        }

        // Now check password if nothing else validated the user
        if(request.correctFilePassword) {
            // User allowed to access folder, continue:
            // Update downloadCount
            requestedFile.downloadCount++;
            await requestedFile.save();
            // Download file for user
            return response.download(requestedFile.pathToFile, requestedFile.name);
        }
        else {
            return response.render("password");
        }

        
        return response.status(403).send("No permissions to view this file."); 
    }
)

// Used for attempting to download a file with a given id, with password provided
app.post("/file/:id",
    checkSchema(fileValidationSchema), // Validate password is valid (if given)
    validateFile, // attach request.file if exists, returns err if otherwise
    checkOwnership, // attach request.isFileOwner
    checkWhitelist, // attach request.passesFileViewWhitelist
    resolveFiletoParentFolder,// Idea: Middleware to attach request.folder for parent folder (if exists)
    checkFolderWhitelist, //  // Adds .canViewFolder .canDeleteFolder .canEditFolder to request based on request.folder
    checkFolderOwnership, // Adds request.isFolderOwner
    checkPasswordForFile, // Adds request.correctFilePassword
    async (request, response) => {
        console.log("Inside POST /file/:id");

        const requestedFile = request.file;

        if(request.folder) { // If file is in a parent folder
            if(!(request.isFolderOwner || request.canViewFolder)) {
                return response.status(403).send("No permissions to download files within the parent folder"); 
            }
            // User allowed to access folder, continue:
            // Update downloadCount
            requestedFile.downloadCount++;
            await requestedFile.save();
            // Download file for user
            return response.download(requestedFile.pathToFile, requestedFile.name);
        }


        // Now consider case where there's no parent folder:
        if(request.isFileOwner || request.passesFileViewWhitelist) {
            // User allowed to access folder, continue:
            // Update downloadCount
            requestedFile.downloadCount++;
            await requestedFile.save();
            // Download file for user
            return response.download(requestedFile.pathToFile, requestedFile.name);
        }

        // Now check password if nothing else validated the user
        if(request.correctFilePassword) {
            // User allowed to access folder, continue:
            // Update downloadCount
            requestedFile.downloadCount++;
            await requestedFile.save();
            // Download file for user
            return response.download(requestedFile.pathToFile, requestedFile.name);
        }
        else {
            return response.render("password");
        }

        
        return response.status(403).send("No permissions to view this file."); 
    }
)




// Home page for logged in users, will display options (create new folder, upload new file), view user's current folders and uploaded files
// Output array of files belonging to user, array of folders belonging to user
app.get("/acc/home",
    async (request, response) => {
        if(!request.user) { // If NOT logged in
            return response.redirect("/login"); // Redirect to login page
        }

        // User is logged in, so redirect to homepage
        renderHomepage(request, response);
    }
)




// Specifically for logged in users, will attempt to view the folder of the given folder ID
// Input: Folder id
// Output: If folder exists + correct permissions, will return array of files that belong in the folder
app.get("/acc/folder/:id",
    checkSchema(fileValidationSchema), // Validates folder password is valid
    validateFolder, // Adds request.folder if folder request is valid
    checkFolderOwnership, // Adds .isFolderOwner to request
    checkFolderWhitelist, //  // Adds .canViewFolder .canDeleteFolder .canEditFolder to request
    checkPasswordForFolder, // Adds request.correctFolderPassword
    async (request, response) => {
        console.log("Inside GET /acc/folder/:id");
        console.log(request.isFolderOwner);
        console.log(request.canViewFolder);
        console.log(request.canDeleteFolder);
        console.log(request.canEditFolder);
        console.log(request.correctFolderPassword);
        /*
            TODO:
            if(owns file or .canViewFolder or is public folder):
                Render folderView
            else if(folder has password and user enters it correctly):
                Grant them temp session access via req.session.tempFolderAccess 
            else:
                Reject user
        */

        

        const folder = request.folder;
        const listOfContainedFiles = await Promise.all(folder.filesContained.map(async (curFileId) => {
            return await File.findById(curFileId); 
        })); // Will return list of File objects contained by the Folder

        const listOfContainedFilesNames = listOfContainedFiles.map((file) => file.name);

        const folderName = folder.name;
        const folderOwner = await User.findById(folder.owner);
        const folderOwnerName = folderOwner.username;

        // "/upload"
        // Generate link to folder upload page
        const folderUploadLink = `${request.protocol}://${request.get('host')}/upload?parentFolderID=` + folder.id;
        const homepageLink = `${request.protocol}://${request.get('host')}/acc/home`;
        console.log(folderUploadLink);

        console.log(folderOwnerName);

        const canEdit = request.canEditFolder;
        let canView = request.canViewFolder;
        const canDelete = request.canDeleteFolder;

        const isLoggedIn = request.user != null;
        const isOwner = request.isFolderOwner;

        // Either user entered right password or they already have previously
        if((folder.password != null && request.correctFolderPassword) || (request.session.tempFolderAccess != null && request.session.tempFolderAccess.includes(folder.id))) {
            // Grant temp access to folder
            if(!request.session.tempFolderAccess) {
                request.session.tempFolderAccess = [];
            }
            request.session.tempFolderAccess.push(folder.id); // Add current folder id to list of temporary access folders for cur session

            canView = true; // Can view if they have password
            return response.render("folderView", {folderUploadLink, isOwner, listOfContainedFilesNames, folderName, folderOwnerName, canEdit, canView, canDelete, isLoggedIn, homepageLink}); // TODO: Create page to show all folder content
        }


        if(!request.folder.isPrivate || request.isFolderOwner || request.canViewFolder) { // requested folder is public, no special check needed
            return response.render("folderView", {folderUploadLink, isOwner, listOfContainedFilesNames, folderName, folderOwnerName, canEdit, canView, canDelete, isLoggedIn, homepageLink}); // TODO: Create page to show all folder content
        }

        if(folder.password) {
            return response.render("password");
        }

        
        return response.send("Unauthorized to view folder"); // Unauthorized to view folder
        


    }
)

app.post("/acc/folder/:id",
    checkSchema(fileValidationSchema), // Validates folder password is valid
    validateFolder, // Adds request.folder if folder request is valid
    checkFolderOwnership, // Adds .isFolderOwner to request
    checkFolderWhitelist, //  // Adds .canViewFolder .canDeleteFolder .canEditFolder to request
    checkPasswordForFolder, // Adds request.correctFolderPassword
    async (request, response) => {
        console.log("Inside GET /acc/folder/:id");
        console.log(request.isFolderOwner);
        console.log(request.canViewFolder);
        console.log(request.canDeleteFolder);
        console.log(request.canEditFolder);
        console.log(request.correctFolderPassword);
        /*
            TODO:
            if(owns file or .canViewFolder or is public folder):
                Render folderView
            else if(folder has password and user enters it correctly):
                Grant them temp session access via req.session.tempFolderAccess 
            else:
                Reject user
        */

        

        const folder = request.folder;
        const listOfContainedFiles = await Promise.all(folder.filesContained.map(async (curFileId) => {
            return await File.findById(curFileId); 
        })); // Will return list of File objects contained by the Folder

        const listOfContainedFilesNames = listOfContainedFiles.map((file) => file.name);

        const folderName = folder.name;
        const folderOwner = await User.findById(folder.owner);
        const folderOwnerName = folderOwner.username;

        // "/upload"
        // Generate link to folder upload page
        const folderUploadLink = `${request.protocol}://${request.get('host')}/upload?parentFolderID=` + folder.id;
        const homepageLink = `${request.protocol}://${request.get('host')}/acc/home`;
        console.log(folderUploadLink);

        console.log(folderOwnerName);

        const canEdit = request.canEditFolder;
        let canView = request.canViewFolder;
        const canDelete = request.canDeleteFolder;
        const isLoggedIn = request.user != null;

        const isOwner = request.isFolderOwner;

        // Either user entered right password or they already have previously
        if((folder.password != null && request.correctFolderPassword) || (request.session.tempFolderAccess != null && request.session.tempFolderAccess.includes(folder.id))) {
            // Grant temp access to folder
            if(!request.session.tempFolderAccess) {
                request.session.tempFolderAccess = [];
            }
            request.session.tempFolderAccess.push(folder.id); // Add current folder id to list of temporary access folders for cur session

            canView = true; // Can view if they have password
            return response.render("folderView", {folderUploadLink, isOwner, listOfContainedFilesNames, folderName, folderOwnerName, canEdit, canView, canDelete, isLoggedIn, homepageLink}); // TODO: Create page to show all folder content
        }


        if(!request.folder.isPrivate || request.isFolderOwner || request.canViewFolder) { // requested folder is public, no special check needed
            return response.render("folderView", {folderUploadLink, isOwner, listOfContainedFilesNames, folderName, folderOwnerName, canEdit, canView, canDelete, isLoggedIn, homepageLink}); // TODO: Create page to show all folder content
        }

        if(folder.password) {
            return response.render("password");
        }

        
        return response.send("Unauthorized to view folder"); // Unauthorized to view folder
        


    }
)


app.get("/acc/createFolder",
    (request, response) => {
        if(request.user == null) { // User not logged in, redirect to /login
            response.redirect("/login");
        }
        response.render("folderCreationPage");
    }
)


// This is for logged in users who want to create a folder
// Input: folderName, isPrivate, user (of course)
// If isPrivate: Provide: List of whitelisted usernames whitelistView, whitelistAdd, password is optional
// Output: Success message, or reason for failure
app.post("/acc/createFolder",
    checkSchema(folderValidationScema), // Checks if password is valid + folder name + isPrivate
    verifyPrivateWhitelist, // Verify whitelists are valid, adds request.viewWhitelist, request.editWhitelist and request.deleteWhitelist
    upload.single("file"),
    async (request, response) => {
        console.log("Inside POST /acc/createFolder");

        if(request.user == null) { // Not logged in
            return response.redirect("/login");
        }

        const errors = validationResult(request);

        if(!errors.isEmpty) {
            return request.send("Errors");
        }

        const data = matchedData(request);

        const folderName = data.name;
        const isPrivate = data.isPrivate;
        console.log(isPrivate);

        const fileData = {
            isPrivate: isPrivate,
            name: folderName,
            owner: request.user.id,
            filesContained: [],
            viewWhitelist: [],
            editWhitelist: [],
            deleteWhitelist: []
        }


        if(isPrivate) {
            const password = hashPassword(data.password);
            const viewWhitelist = request.viewWhitelist;
            const editWhitelist = request.editWhitelist;
            const deleteWhitelist = request.deleteWhitelist;

            fileData.password = password;
            fileData.viewWhitelist = viewWhitelist;
            fileData.editWhitelist = editWhitelist;
            fileData.deleteWhitelist = deleteWhitelist;
        }

    
        newFolder = new Folder(fileData);

        await newFolder.save();
        
        console.log("Created folder:")
        console.log(newFolder);

        const linkToViewNewFolder = '/acc/folder/' + newFolder.id;

        response.redirect(linkToViewNewFolder);
    }
)


app.post("/acc/folder/delete/:id",
    validateFolder, // Adds request.folder if folder request is valid
    checkFolderOwnership, // Adds .isFolderOwner to request
    (request, response) => {
        if(request.folder) { // If requested folder to delete exists
            if(request.isFolderOwner) {
                deleteFolder(request.folder);
                response.redirect("/acc/home");
            }
            else {
                return response.send("Folder doesn't belong to you. Only owner can delete it");
            }
        }
        else {
            return response.send("Invalid folder");
        }
    }

);


app.get("/acc/file/edit",
    (request, response) => {
        
    }
)











// Starts up server by listening on a port for HTTP requests
app.listen(PORT, () => {
    // Here you can have something occur when the server starts up
    console.log(`Running on 3000`)
}); 

