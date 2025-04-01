// Modules
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



// Input: Password
// Output: Hash of password
const hashPassword = (password) => {
    const salt = bcrypt.genSaltSync(10);
    return bcrypt.hashSync(password, salt);
}


// Input: request.file, request.folder if has parent folder
// Output: Delete given file, returns true upon successful deletion, false if otherwise
const deleteFile = async (file) => { 
    // Delete file

    try {
        // Delete file from filesystem
        fs = require('fs')
        console.log("1");
        await fs.unlink(file.pathToFile, (err) => {
            if (err) {
                console.error(err)
                return false; // Error deleting file
            }})
        console.log("2");

        // If file has a parent folder, remove it from the folder's filesContained array
        if (file.parentFolder != null) {
            const parentFolder = await Folder.findById(file.parentFolder.id);
            parentFolder.filesContained = parentFolder.filesContained.filter(curFile => curFile.toString() !== file.id);
            await parentFolder.save();
            
        }

        // Delete the file metadata from MongoDB
        console.log(file.id);
        await File.findByIdAndDelete(file.id);
        return true;
    } catch (err) {
        console.error("Error deleting file:", err);
        return false;
    }
}

// Renders a page which displays details about the file
// Input: Requires request.file to be present (preverified)
// Output: fileView.ejs with corresponding values
const renderFileView = (req, res) => {
    const requestedFile = req.file;
    const requestedFileName = requestedFile.name;
    const requestedFileDownloadCount = requestedFile.downloadCount;
    const requestedFileLink = `${req.protocol}://${req.get('host')}/file/${requestedFile.id}`;

    res.render("fileView", { fileName: requestedFileName, fileLink: requestedFileLink, downloadCount: requestedFileDownloadCount });
};



const renderHomepage = async (request, response) => {
    // Now user is logged in, so display some basic info, such as created folders, uploaded files
    const files = await File.find({ owner: request.user.id });
    const folders = await Folder.find({ owner: request.user.id });
    const fileNames = files.map((file) => file.name);
    const folderNames = folders.map((folder) => folder.name);
    const username = request.user.username;
    console.log(files);


    // Generate a list of links to view details about each file's info: (format: http://localhost:3000/file/view/[file id])
    // Generate file detail links
    const fileDetailLinks = files.map((curFile) => 
    `${request.protocol}://${request.get('host')}/file/view/${curFile.id}`
    );

    const viewFolderLinks = folders.map((curFolder) => 
        `${request.protocol}://${request.get('host')}/acc/folder/${curFolder.id}`
        );



    // Generate list of links to delete file (format http://localhost:3000/file/delete/[file id])
    const fileDeletionLinks = files.map((curFile) => 
        `${request.protocol}://${request.get('host')}/file/delete/${curFile.id}`
        );
    
    // Generate link to upload page
    const uploadLink = `${request.protocol}://${request.get('host')}/upload/`;

    // Generate link to folder creation page
    const createFolderLink = `${request.protocol}://${request.get('host')}/acc/createFolder`;
    
    


    // Render homepage
    response.render("accountHomepage", {fileNames, username, fileDetailLinks, fileDeletionLinks, uploadLink, createFolderLink, viewFolderLinks, folderNames});
}

module.exports = {hashPassword, deleteFile, renderFileView, renderHomepage};