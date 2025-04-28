require('dotenv').config(); 
const crypto = require("crypto");
const SESSION_SECRET = crypto.randomBytes(64).toString('hex');

process.env.ME_CONFIG_SITE_COOKIESECRET = SESSION_SECRET;
process.env.ME_CONFIG_SITE_SESSIONSECRET = SESSION_SECRET;

// Import modules
const express = require("express");
const multer = require('multer');
const mongoose = require("mongoose");
const File = require("../models/File.js");
const bcrypt = require("bcrypt");
const session = require('express-session'); // Import to use use sessions
const cookieParser = require('cookie-parser'); // Import to parse cookies (like session cookies)
// Multer processes files in the multipart/form-data format. (middleware)
const passport = require("passport"); 
const upload = multer({dest: "uploads"})
require("../strategies/local-strategy.js"); // Import our local strategy for Passport.js authentication
const User = require('../models/User.js'); // Import our mongoose User object
const Folder = require('../models/Folder.js'); // Import our mongoose Folder object
const MongoStore = require("connect-mongo"); // Import connect-mongo for creating a persistent session store
const {query, validationResult, body, matchedData, checkSchema} = require('express-validator'); // Import express-validator
const csurf = require("csurf");
const csrfProtection = csurf({ cookie: true });







// Import middlewares:
const {validateFile, validateFolder, checkOwnership, checkFolderOwnership, checkWhitelist, checkFolderWhitelist, folderValidationCheck, multerFileValidationCheck, verifyPrivateWhitelist, resolveFiletoParentFolder, resolveFolderIDtoFolder, checkPasswordForFile, checkPasswordForFolder, getParentFolder} = require("../utils/middlewares.js");

// Validation schemas
const userValidationSchema = require("../validationSchemas/userValidationSchema.js");
const fileValidationSchema = require("../validationSchemas/fileValidationSchema.js");
const folderValidationScema = require("../validationSchemas/folderValidationSchema.js");


// Import helper functions
const {hashPassword, deleteFile, renderFileView, renderHomepage, deleteFolder, renderFilePermissions, parseAndValidateList, modifyFilePermissions, modifyFilePassword, renderFolderPermissions, modifyFolderPassword, modifyFolderPermissions} = require('../utils/helpers.js'); 
const { csrf } = require("lusca");





mongoose
    .connect("mongodb://localhost/fileDatabase")
    .then(() => console.log('Connected to database'))
    .catch((err) => console.log(`Error: ${err}`));

// Constants
const PORT = 3000;

const app = express();

// Global middleware

var mongo_express
var mongo_express_config

const { createProxyMiddleware } = require('http-proxy-middleware');







app.use(session({ 
    secret: SESSION_SECRET, 
    saveUninitialized: false,
    resave: false,
    cookie: {
        maxAge: 60000 * 60 * 24 * 7
    },
    store: MongoStore.create({ // For creating the persistent session store
        client: mongoose.connection.getClient()
    })
}));




app.use(cookieParser(SESSION_SECRET)); // cookieParser must use same secret value as session

// Middleware to parse content-type json bodies in request, allows request.body to be defined
app.use(express.urlencoded({extended: true })); 
app.use(express.json());



app.use(passport.initialize());
app.use(passport.session()); //


// CSRF stuff
app.use(function (err, req, res, next) {
    switch (err.code) {
      case 'EBADCSRFTOKEN':
        break
      case 'LIMIT_FILE_SIZE':
        break
    }
  })
  const { spawn } = require('child_process');

  // Nonce-generator middleware
app.use((req, res, next) => {
    res.locals.nonce = crypto.randomBytes(16).toString('base64');
    next();
  });

const me = spawn('npx', [
    'mongo-express',
    '--url',  'mongodb://localhost:27017',  // full connection string
    '--port', '3100'
    ], {
    stdio: 'inherit',
    env: {
        ...process.env,
        ME_CONFIG_MONGODB_URL:            'mongodb://localhost:27017',
        ME_CONFIG_MONGODB_ENABLE_ADMIN:   'true',      
        ME_CONFIG_SITE_COOKIESECRET:      SESSION_SECRET,
        ME_CONFIG_SITE_SESSIONSECRET:     SESSION_SECRET,
        ME_CONFIG_BASICAUTH_ENABLED:      'true',      
        ME_CONFIG_BASICAUTH_USER:         'admin',
        ME_CONFIG_BASICAUTH_PASS:         'pass'
    }
});  




// Set up EJS as the view engine, must use before response.render() will work
app.set("view engine", "ejs");



app.get('/admin', (req, res) => {
    res.redirect('http://localhost:3100');
  });
// Pages
app.get("/", // Home page
    (request, response) => {
        // Will look for view template called index, usually in folder "views"
        const folderUploadLink = `${request.protocol}://${request.get('host')}/upload`;
        const loginLink = `${request.protocol}://${request.get('host')}/login`;
        const registerLink = `${request.protocol}://${request.get('host')}/register`;
        response.render("home", {folderUploadLink, loginLink, registerLink});  

    }
)




// For registering for an account. If user is already logged in, will just redirect to /acc
// Input: Accepts username, password, email
// Output: Errors if invalid input, will redirect to /login upon success
app.post("/register",
    csrfProtection,
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
    csrfProtection,
    (request, response) => {
        console.log("Inside GET /register");
        if(request.user) { // If logged in
            response.redirect("/acc/home"); // If user is already logged in, will just redirect to /acc/home
        }
        else {
            csrfToken = request.csrfToken();
            response.render("registerPage", {csrfToken}); // Display register page
        }
    }
)



// For logging in. If user is already logged in, will just redirect to /acc
// Input: Username, password
// Output: Error message upon failure, redirect to /acc if successful, possibly alongside info like username
app.post("/login",
    csrfProtection,
    passport.authenticate("local"), 
    (request, response) => {
        if(request.user == null) { // If login not successful
            // Return back to /index, and send the link to the file back:
            response.render("loginPage",  {msg : `Invalid credentials, please try again.`});
        }

        response.redirect("/acc/home");
    }
)


app.get("/login",
    csrfProtection,
    (request, response) => {
        if(request.user) { // If logged in
            return response.redirect("/acc/home"); // If user is already logged in, will just redirect to /acc
        }
        else {
            csrfToken = request.csrfToken();
            return response.render("loginPage", {csrfToken}); // Display register page
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
    csrfProtection,
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
        csrfToken = request.csrfToken();
        response.render("index", {fileLink : `${request.headers.origin}/file/${newFile.id}`, csrfToken} );
})


app.get("/upload", 
    csrfProtection,
    (request, response) => {
        console.log("Inside GET /upload");
        csrfToken = request.csrfToken();
        if(request.query.parentFolderID != null) { // If uploading to a folder, pass the parentFolderID for the upload
            const parentFolderID = request.query.parentFolderID;
            console.log(parentFolderID);
            return response.render("index", {parentFolderID: parentFolderID, csrfToken});
        }
        // Otherwise not needed
        return response.render("index", {csrfToken});
    }
)


// Input: File id as route paramter, password (optional), request.user
// Output: Will display file if passed access controls

app.get("/file/view/:id",  
    checkSchema(fileValidationSchema), // Validate password is valid (if given)
    csrfProtection,
    validateFile, // attach request.file if exists, returns err if otherwise
    checkOwnership, // attach request.isFileOwner
    checkWhitelist, // attach request.passesFileViewWhitelist
    resolveFiletoParentFolder,// Idea: Middleware to attach request.folder for parent folder (if exists)
    checkFolderWhitelist, //  // Adds .canViewFolder .canDeleteFolder .canEditFolder to request based on request.folder
    checkFolderOwnership, // Adds request.isFolderOwner
    checkPasswordForFile, // Renders password entering page if missing or incorrect
    (request, response) => {
        console.log("Inside GET /file/view/:id");


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
            return response.render("password");
        }

    }
)

// If we need to enter password to view the file details
app.post("/file/view/:id", 
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
    }
)



// Specifically for logged in users, will attempt to delete the file (assuming they own it + it exists)
// Input: fileName
// Output: Success or failure + error message
app.post("/file/delete/:id",
    validateFile, // attach request.file if exists, returns err if otherwise
    checkOwnership, // attach request.isFileOwner
    checkWhitelist, // attach request.canViewFile
    getParentFolder,// Idea: Middleware to attach request.folder for parent folder (if exists)
    checkFolderWhitelist, //  // Adds .canViewFolder .canDeleteFolder .canEditFolder to request based on request.folder
    checkFolderOwnership, // Adds request.isFolderOwner
    checkPasswordForFile, // Will redirect to password screen if password needed but not given or incorrect
    async (request, response) => {
        console.log("Inside POST /file/delete")
        if(request.folder) { // If file is in folder
            if(!request.folder.isPrivate) { // If folder is public
                await deleteFile(request.file);
                return response.redirect("/acc/folder/" + request.folder.id); // Go to folder view

            }
            if(request.isFolderOwner || request.canDeleteFolder) {
                await deleteFile(request.file);
                return response.redirect("/acc/folder/" + request.folder.id); // Go to folder view
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

       
        const folder = request.folder;
        const listOfContainedFiles = await Promise.all(folder.filesContained.map(async (curFileId) => {
            return await File.findById(curFileId); 
        })); // Will return list of File objects contained by the Folder

        const listOfContainedFilesNames = listOfContainedFiles.map((file) => file.name);
        const listOfContainedFilesDownloadLinks = listOfContainedFiles.map((file) => `${request.protocol}://${request.get('host')}/file/` + file.id);
        const listOfContainedFilesDeleteLinks = listOfContainedFiles.map((file) => `${request.protocol}://${request.get('host')}/file/delete/` + file.id);
        const listOfContainedFileUploaders = await Promise.all(
            listOfContainedFiles.map(async (file) => {
              if (file.owner) {
                const user = await User.findById(file.owner);
                return user ? user.username : "Guest user";
              }
              return "Guest user";
            })
          );


          console.log(listOfContainedFileUploaders);
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
            return response.render("folderView", {folderUploadLink, isOwner, listOfContainedFilesNames, folderName, folderOwnerName, canEdit, canView, canDelete, isLoggedIn, homepageLink, listOfContainedFilesDownloadLinks, listOfContainedFilesDeleteLinks, listOfContainedFileUploaders}); 
        }


        if(!request.folder.isPrivate || request.isFolderOwner || request.canViewFolder) { // requested folder is public, no special check needed
            return response.render("folderView", {folderUploadLink, isOwner, listOfContainedFilesNames, folderName, folderOwnerName, canEdit, canView, canDelete, isLoggedIn, homepageLink, listOfContainedFilesDownloadLinks, listOfContainedFilesDeleteLinks, listOfContainedFileUploaders}); 
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

        

        

        const folder = request.folder;
        const listOfContainedFiles = await Promise.all(folder.filesContained.map(async (curFileId) => {
            return await File.findById(curFileId); 
        })); // Will return list of File objects contained by the Folder

        const listOfContainedFilesNames = listOfContainedFiles.map((file) => file.name);
        const listOfContainedFilesDownloadLinks = listOfContainedFiles.map((file) => `${request.protocol}://${request.get('host')}/file/` + file.id);
        const listOfContainedFilesDeleteLinks = listOfContainedFiles.map((file) => `${request.protocol}://${request.get('host')}/file/delete/` + file.id);

        const listOfContainedFileUploaders = await Promise.all(
            listOfContainedFiles.map(async (file) => {
              if (file.owner) {
                const user = await User.findById(file.owner);
                return user ? user.username : "Guest user";
              }
              return "Guest user";
            })
          );

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
            return response.render("folderView", {folderUploadLink, isOwner, listOfContainedFilesNames, folderName, folderOwnerName, canEdit, canView, canDelete, isLoggedIn, homepageLink, listOfContainedFilesDownloadLinks, listOfContainedFilesDeleteLinks, listOfContainedFileUploaders}); 
        }


        if(!request.folder.isPrivate || request.isFolderOwner || request.canViewFolder) { // requested folder is public, no special check needed
            return response.render("folderView", {folderUploadLink, isOwner, listOfContainedFilesNames, folderName, folderOwnerName, canEdit, canView, canDelete, isLoggedIn, homepageLink, listOfContainedFilesDownloadLinks, listOfContainedFilesDeleteLinks, listOfContainedFileUploaders}); 
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
            const viewWhitelist = request.viewWhitelist;
            const editWhitelist = request.editWhitelist;
            const deleteWhitelist = request.deleteWhitelist;

            if(data.password) {
                const password = hashPassword(data.password);
                fileData.password = password;
            }
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
    async (request, response) => {
        if(request.folder) { // If requested folder to delete exists
            if(request.isFolderOwner) {
                await deleteFolder(request.folder);
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


// Output: Page displaying: Current users in various whitelists, isPrivate status, 
app.get("/file/permissions/:id",
    validateFile, // attach request.file if exists, returns err if otherwise
    checkOwnership, // attach request.isFileOwner
    resolveFiletoParentFolder,// Idea: Middleware to attach request.folder for parent folder (if exists)
    checkFolderOwnership, // Adds request.isFolderOwner
    async (request, response) => {
        if(!request.user) { // User not logged in
            response.redirect("/login");
        }


        if(request.folder) { // If file attempting to modify permissions for is in folder
            if(!request.isFolderOwner) {
                response.send("Cannot modify permissions for files inside folder you don't own.");
            }
            return await renderFilePermissions(request, response, request.file);
        }

        // Now check if user owns file
        if(request.isFileOwner) {
            return await renderFilePermissions(request, response, request.file);
        }
        response.send("Cannot modify permissions for files you don't own.");
    }
);




// Input: isPrivate (IE nullify viewWhitelist for file), file ID, password (To replace old one), addWhitelist, removeWhitelist (To modify file.viewWhitelist)
app.post("/file/permissions/:id",
    validateFile, // attach request.file if exists, returns err if otherwise
    checkOwnership, // attach request.isFileOwner
    resolveFiletoParentFolder,// Idea: Middleware to attach request.folder for parent folder (if exists)
    checkFolderOwnership, // Adds request.isFolderOwner
    async (request, response) => {
        console.log("Inside POST /file/permissions");
        if(!request.user) { // User not logged in
            response.redirect("/login");
        }

        const addWhitelist = await parseAndValidateList(response, request.body.addWhitelist);
        const removeWhitelist = await parseAndValidateList(response, request.body.removeWhitelist);
        const isPrivate = request.body.isPrivate === "true";
        const newPassword = request.body.password;


        if(request.folder) { // If file attempting to modify permissions for is in folder
            if(!request.isFolderOwner) {
                return response.send("Cannot modify permissions for files inside folder you don't own.");
            }
            await modifyFilePermissions(isPrivate, request.file, addWhitelist, removeWhitelist);
            if(newPassword) {
                await modifyFilePassword(request.file, newPassword);
            }
            return await renderFilePermissions(request, response, request.file);
        }

        // Now check if user owns file
        if(request.isFileOwner) {
            await modifyFilePermissions(isPrivate, request.file, addWhitelist, removeWhitelist);
            if(newPassword) {
                await modifyFilePassword(request.file, newPassword);
            }
            return await renderFilePermissions(request, response, request.file);
        }
        return response.send("Cannot modify permissions for files you don't own.");
    }
);


// Input: request.user, folder ID
// Output: Will display permissions modification page if user logged in and folder ID is valid and they own its valid
app.get("/folder/permissions/:id",
    validateFolder, // Adds request.folder if folder request is valid
    checkFolderOwnership, // Adds .isFolderOwner to request
    async (request, response) => {
        if(!request.user) { // User not logged in
            response.redirect("/login");
        }

        if(request.isFolderOwner) {
            return await renderFolderPermissions(request, response, request.folder);
        }
        else {
            response.send("Cannot modify folder permissions for folder you don't own.")
        }
    }
)


// Input: isPrivate, editWhitelistAdd editWhitelistRemove, viewWhitelistAdd viewWhitelistRemove, deleteWhitelistAdd deleteWhitelistRemove, password
// Output: If the user owns the folder, the permsisions will be modified
app.post("/folder/permissions/:id",
    validateFolder, // Adds request.folder if folder request is valid
    checkFolderOwnership, // Adds .isFolderOwner to request
    async (request, response) => {
        console.log("Inside POST /file/permissions");
        if(!request.user) { // User not logged in
            return response.redirect("/login");
        }
        if(!request.isFolderOwner) {
            return response.send("Cannot modify folder permissions for folder you don't own.")
        }

        const viewWhitelistAdd = await parseAndValidateList(response, request.body.viewWhitelistAdd);
        const viewWhitelistRemove = await parseAndValidateList(response, request.body.viewWhitelistRemove);
        console.log(viewWhitelistAdd, viewWhitelistRemove);

        const editWhitelistAdd = await parseAndValidateList(response, request.body.editWhitelistAdd);
        const editWhitelistRemove = await parseAndValidateList(response, request.body.editWhitelistRemove);
        console.log(editWhitelistAdd, editWhitelistRemove);

        const deleteWhitelistAdd = await parseAndValidateList(response, request.body.deleteWhitelistAdd);
        const deleteWhitelistRemove = await parseAndValidateList(response, request.body.deleteWhitelistRemove);
        console.log(deleteWhitelistAdd, deleteWhitelistRemove);
        


        const isPrivate = request.body.isPrivate === "true";
        console.log(request.body.isPrivate);
        const newPassword = request.body.password;


        if(!request.isFolderOwner) {
            return response.send("Cannot modify permissions for folder you don't own.");
        }

        await modifyFolderPermissions(isPrivate, request.folder, viewWhitelistAdd, viewWhitelistRemove, editWhitelistAdd, editWhitelistRemove, deleteWhitelistAdd, deleteWhitelistRemove);
        if(newPassword) {
            await modifyFolderPassword(request.folder, newPassword);
        }
        return await renderFolderPermissions(request, response, request.folder);
    }
)









// Starts up server by listening on a port for HTTP requests
app.listen(PORT, () => {
    // Here you can have something occur when the server starts up
    console.log(`Running on 3000`)
}); 


module.exports = app;

