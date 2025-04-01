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
const sanitizeFilename = require("sanitize-filename"); // For sanitizing multer filename input



// Will validate that a given file of route parameter id actually exists
// Input: request with file id route parameter
// Output: If file of given id exists, will attach as request.file
const validateFile = async (req, res, next) => {

    if (!mongoose.Types.ObjectId.isValid(req.params.id)) { // Check if given request parameter id is valid or not
        return res.status(400).send("Invalid file ID");
    }

    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).send("File not found");

    req.file = file; // Attach file to request for next middlewares
    next();
};

// Will validate that a given folder of route parameter id actually exists
// Input: request with folder id route parameter
// Output: If folder of given id exists, will attach as request.folder, null otherwise
const validateFolder = async (request, response, next) => {

    if (!mongoose.Types.ObjectId.isValid(request.params.id)) { // Check if given request parameter id is valid or not
        return response.status(400).send("Invalid folder ID");
    }

    const folder = await Folder.findById(request.params.id);
    if (!folder) return response.status(404).send("Folder not found");

    request.folder = folder; // Attach folder to request for next middlewares
    next();
}

// Check If User Is the Owner of the file
// Input: Expects request.file
// Output: Will attach isFileOwner to request
const checkOwnership = (req, res, next) => {
    if (req.user && req.file.owner.id.toString("hex") === req.user.id) { // If user is logged in and if user is owner of the file
        req.isFileOwner = true;
        return next();
    }
    req.isFileOwner = false;
    return next(); // Continue to whitelist or password check
};

// Check If User Is the Folder Owner
const checkFolderOwnership = (request, response, next) => {
    if(request.folder) { // If request folder exists
        request.isFolderOwner = (request.user && request.folder.owner.id.toString("hex") === request.user.id);
    }
    else {
        request.isFolderOwner = false; // Default to false for nonexistent folder
    }
    next(); // Continue to whitelist or password check
};

// Check Whitelist Access for file
// Input: Expects request.file and request.user
// Output: .canViewFile attached to request
const checkWhitelist = (request, response, next) => {
    const file = request.file;
    const viewerUser = request.user

    if(file.viewWhitelist != null) { // If file whitelist is active
        if(viewerUser == null) {
            request.canViewFile = false; // Non logged in viewer trying to access
        }
        else {
            request.canViewFile = file.viewWhitelist.includes(viewerUser.id);
        }
    }
    else {
        request.canViewFile = true; // Default to can view if whitelist is off
    }
    return next();
};

// Check Whitelist Access controls for folder
// Input: Expects request.folder and request.user
// Output: .canViewFolder, .canEditFolder, .canDeleteFolder attached to request
const checkFolderWhitelist = (request, response, next) => {
    const folder = request.folder;
    const viewerUser = request.user

    if(request.isPrivate) {
        if(viewerUser == null) { // User not logged in but trying to view private folder
            request.canViewFolder = false;
            request.canEditFolder = false;
            request.canDeleteFolder = false;
        }
        else {
            request.canViewFolder = folder.viewWhitelist.includes(viewerUser.id);
            request.canEditFolder = folder.editWhitelist.includes(viewerUser.id);
            request.canDeleteFolder = folder.deleteWhitelist.includes(viewerUser.id);
        }
    }
    else { // Folder is public, default to full permissions for all
        request.canViewFolder = true;
        request.canEditFolder = true;
        request.canDeleteFolder = true;
    }
    return next();
};

// Check Password Access for file (TODO)
const checkPassword = (req, res, next) => {
    const passwordErrors = validationResult(req);
    const data = matchedData(req);

    if(!passwordErrors.isEmpty()) {
        return res.render("password", { msg: "Invalid password entered. Try again." });
    }
    
    if (req.file.password) { // If requested file needs password
        if (!data.password) { // No input password given
            return res.render("password", { msg: "Enter password to access this file" });
        }
        if (!bcrypt.compareSync(data.password, req.file.password)) { // If wrong password
            return res.render("password", { msg: "Incorrect password. Try again" });
        }
    }
    next();
};




// Input: request.params.parentFolderID
// Output: request.folder, request.isFolderOwner, request.canEditFolder
const folderValidationCheck = async (request, response, next) => {
    console.log("Inside folderValidationCheck middleware");
    const parentFolderID = request.query.parentFolderID;
    if(parentFolderID != null) { // Uploading to a folder
        request.params.id = parentFolderID;
        // Clean up any provided values before continuing
        request.folder = null;
        request.isFolderOwner = null;
        request.canEditFolder = null;

        await validateFolder(request, response, () => {});// Will add request.folder if parentFolderID is actually valid
        await checkFolderOwnership(request, response, () => {}); // Will add request.isFolderOwner 
        await checkFolderWhitelist(request, response, () => {}); // Will add request.canEditFolder

        console.log(request);

        if(request.folder) { // Requested parent folder exists
            if(request.isFolderOwner || request.canViewFolder) {
                console.log("testing1");
                return next(); // Continue onto upload middleware
            }
        }

        // Some check failed
        return response.sendStatus(403); // Forbidden from uploading file to specified folderID, won't run upload middleware
    }
    return next();
}


// Input: request.isPrivate, request.body.viewWhitelistUsernames string
// Output: If file isPrivate, will verify all usernames in viewWhitelistUsernames actually are users, and add request.viewWhitelist[], which contains array of user IDs instead of usernames
const verifyPrivateWhitelist = async (request, response, next) => {
    console.log("Inside verifyPrivateWhitelist");
    request.viewWhitelist = null; // Reset anything user provided
    if (request.body.isPrivate) { 
        try {
            if(request.folder) { // If trying to upload to folder with custom whitelist, invalid, folder whitelist takes precedence
                return response.status(400).send("Folder whitelist takes precendence");
            }
            console.log(request.body.viewWhitelistUsernames);
            request.viewWhitelistUsernames = request.body.viewWhitelistUsernames.trim().split(/\s+/);
            console.log(request.viewWhitelistUsernames)
            // Using Promise.all to wait for all the User lookups
            const users = await Promise.all(
                request.viewWhitelistUsernames.map(async (username) => {
                    const user = await User.findOne({ username: username });
                    return user ? user.id : null; // Return user ID if user exists, or null if not
                })
            );

            // Now check if any usernames were invalid
            if (users.includes(null)) {
                // Remove uploaded data
                fs = require('fs')
                await fs.unlink(request.file.destination, (err) => {
                    if (err) {
                        console.error(err)
                        return false; // Error deleting file
                    }})

                return response.status(400).send("One or more usernames are invalid");
            }

            // Now attach users who are on the viewing whitelist
            request.viewWhitelist = users;

        } catch (error) {
            // Remove uploaded data
            fs = require('fs')
                await fs.unlink(request.file.pathToFile, (err) => {
                    if (err) {
                        console.error(err)
                        return false; // Error deleting file
                    }})

            console.error("Error verifying private whitelist:", error);
            return response.status(500).send("Internal server error");
        }
    }

    next(); // If not private, just proceed
}



const multerFileValidationCheck = (request, response, next) => {
    if (!request.file) {
        return response.status(400).send("No file uploaded");
    }

    // Sanitize the filename (removes dangerous characters)
    const sanitizedFilename = sanitizeFilename(request.file.originalname);

    // Check if filename is empty after sanitization
    if (!sanitizedFilename) {
        return response.status(400).send("Invalid file name");
    }

    // Name is valid
    request.file.originalname = sanitizedFilename;
    return next();

}



// Input: request.file
// Output request.parentFolderID holding the parent folder ID attached, null if file has no parent folder
const resolveFiletoParentFolder = async (request, response, next) => {

    if (!mongoose.Types.ObjectId.isValid(request.params.id)) { // Check if given request parameter id is valid or not
        return response.status(400).send("Invalid folder ID");
    }

    const folder = await Folder.findById(request.params.id);

    request.folder = folder; // Attach folder to request for next middlewares
    next();

    request.folder = request.file.parentFolder; // attach request.folder, null if no parent folder
    return next();
}

// Input request.body.parentFolderID
// Output: Attach request.folder for parent folder, null otherwise
const resolveFolderIDtoFolder = async (request, response, next) => {
    const folderID = request.body.parentFolderID;

    if(folderID == null) { // Skip if there's no folderID to resolve
        request.folder = null;
        next();
    }

    if (!mongoose.Types.ObjectId.isValid(folderID)) { // Check if given request parameter id is valid or not
        return response.status(400).send("Invalid folder ID");
    }

    const folder = await Folder.findById(folderID);

    request.folder = folder; // Attach folder to request for next middlewares
    next();
}


module.exports = {validateFile, validateFolder, checkOwnership, checkFolderOwnership, checkWhitelist, checkFolderWhitelist, checkPassword, folderValidationCheck, multerFileValidationCheck, verifyPrivateWhitelist, resolveFiletoParentFolder, resolveFolderIDtoFolder};