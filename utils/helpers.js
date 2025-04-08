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
const fs = require('fs').promises; // Use the promise-based version



// Input: Password
// Output: Hash of password
const hashPassword = (password) => {
    const salt = bcrypt.genSaltSync(10);
    return bcrypt.hashSync(password, salt);
}


// Input: request.file, request.folder if has parent folder
// Output: Delete given file + metadata, returns true upon successful deletion, false if otherwise
const deleteFile = async (file) => { 
    console.log("Inside helper deleteFile");
    // Delete file

    try {
        // Delete file from filesystem
        await fs.unlink(file.pathToFile);
        // If file has a parent folder, remove it from the folder's filesContained array
        
        if (file.parentFolder != null) {
            const parentFolder = await Folder.findById(file.parentFolder._id);
            parentFolder.filesContained = parentFolder.filesContained.filter(curFile => curFile.toString() !== file.id);
            await parentFolder.save();
            
        }

        // Delete the file metadata from MongoDB (if exists)
        if(file) {
            console.log(file.id);
            await File.findByIdAndDelete(file.id);
        }
        return true;
    } catch (err) {
        console.error("Error deleting file:", err);
        return false;
    }
}

// Input: folder (assumed to be prevalidated and non-null)
// Output: Deletes the folder and all files stored inside it
const deleteFolder = async (folder) => {
    console.log("Inside helper deleteFolder");
    // Assuming folder.filesContained is an array of file IDs (or file objects)
    for (const fileId of folder.filesContained) {
        // If filesContained is just IDs, fetch the file document:
        const file = await File.findById(fileId);
        console.log(file);
        if (file) {
            await deleteFile(file);
        }
    }
    
    // Delete the folder itself from the database
    await Folder.findByIdAndDelete(folder.id);
    return true;
};

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
    
    const folderPermissionLinks = folders.map((curFolder) => 
        `${request.protocol}://${request.get('host')}/folder/permissions/${curFolder.id}`
        );



    // Generate list of links to delete file (format http://localhost:3000/file/delete/[file id])
    const fileDeletionLinks = files.map((curFile) => 
        `${request.protocol}://${request.get('host')}/file/delete/${curFile.id}`
        );
    const filePermissionLinks = files.map((curFile) => 
        `${request.protocol}://${request.get('host')}/file/permissions/${curFile.id}`
        );
    
    const folderDeletionLinks = folders.map((curFolder) => 
        `${request.protocol}://${request.get('host')}/acc/folder/delete/${curFolder.id}`
        );
    
    // Generate link to upload page
    const uploadLink = `${request.protocol}://${request.get('host')}/upload/`;

    // Generate link to folder creation page
    const createFolderLink = `${request.protocol}://${request.get('host')}/acc/createFolder`;
    
    


    // Render homepage
    response.render("accountHomepage", {fileNames, username, fileDetailLinks, fileDeletionLinks, uploadLink, createFolderLink, viewFolderLinks, folderNames, folderDeletionLinks, folderPermissionLinks, filePermissionLinks});
}



const renderFilePermissions = async (request, response, file) => {
    console.log("Inside helper function renderFilePermissions");
    const fileName = file.name;
    const isPrivate = file.viewWhitelist != null;
    const viewWhitelist = file.viewWhitelist;
    const linkToPost = `${request.protocol}://${request.get('host')}/file/permissions/${file.id}`;
    let usersOnViewWhitelist;

    if(viewWhitelist) {
        usersOnViewWhitelist = await Promise.all( // Get whitelist usernames
            viewWhitelist.map(async (userID) => {
              const user = await User.findById(userID);
              return user.username;
            })
          );
    }
    
    console.log(usersOnViewWhitelist)
    response.render("filePermissions", {isPrivate, usersOnViewWhitelist, fileName, linkToPost})
}


// Input: isPrivate, editWhitelistAdd editWhitelistRemove, viewWhitelistAdd viewWhitelistRemove, deleteWhitelistAdd deleteWhitelistRemove
const renderFolderPermissions = async (request, response, folder) => {
    console.log("Inside helper function renderFolderPermissions");

    const folderName = folder.name;
    const isPrivate = folder.viewWhitelist != null;
    const viewWhitelist = folder.viewWhitelist;
    const editWhitelist = folder.editWhitelist;
    const deleteWhitelist = folder.deleteWhitelist;

    const linkToPost = `${request.protocol}://${request.get('host')}/folder/permissions/${folder.id}`;
    let usersOnViewWhitelist;
    let usersOnEditWhitelist;
    let usersOnDeleteWhitelist;

    if(viewWhitelist) {
        usersOnViewWhitelist = await Promise.all( // Get whitelist usernames
            viewWhitelist.map(async (userID) => {
              const user = await User.findById(userID);
              return user.username;
            })
          );
    }

    if(editWhitelist) {
        usersOnEditWhitelist = await Promise.all( // Get whitelist usernames
            editWhitelist.map(async (userID) => {
              const user = await User.findById(userID);
              return user.username;
            })
          );
    }

    if(deleteWhitelist) {
        usersOnDeleteWhitelist = await Promise.all( // Get whitelist usernames
            deleteWhitelist.map(async (userID) => {
              const user = await User.findById(userID);
              return user.username;
            })
          );
    }

    response.render("folderPermissions", {isPrivate, usersOnViewWhitelist, usersOnEditWhitelist, usersOnDeleteWhitelist, folderName, linkToPost})
}


// Input: A list, which should be a string of space-separated usernames
// Output: An array of users corresponding to the usernames, will send out 400 if bad usernames given
const parseAndValidateList = async (response, list) => {
    console.log("Inside helper function parseAndValidateList");
    // Parse the usernames from the request body (if provided)
    if(!list) {
        return [];
    }

    const newList = list
    ? list.trim().split(/\s+/)
    : [];

    // Validate view whitelist: lookup each username and return user ID or null
    const users = await Promise.all(
        newList.map(async (username) => {
            const user = await User.findOne({ username });
            return user ? user._id : null;
        })
    );
    if (users.includes(null)) {
        return response.status(400).send("One or more usernames are invalid");
    }

    return users;

}


/*

const modifyFilePermissions = async (isPrivate, file, addWhitelist, removeWhitelist) => {
    if(!isPrivate) { // File is public
        file.isPrivate = false;
        file.viewWhitelist = null;
    }
    else {

        console.log(addWhitelist);
        console.log(file.viewWhitelist);
        file.viewWhitelist = [...new Set([...(file.viewWhitelist || []), ...addWhitelist])];
        file.viewWhitelist = file.viewWhitelist.filter(item => !removeWhitelist.includes(item));
        
    }

    await file.save();

}
    */


const modifyFilePermissions = async (isPrivate, file, addWhitelist, removeWhitelist) => {
    if (!isPrivate) { // File is public
      file.isPrivate = false;
      file.viewWhitelist = null;
    } else {
      // Convert the existing whitelist and the ones to add/remove into arrays of strings.
      const currentWhitelistStr = (file.viewWhitelist || []).map(item => item.toString());
      const addWhitelistStr = addWhitelist.map(item => item.toString ? item.toString() : item);
      const removeWhitelistStr = removeWhitelist.map(item => item.toString ? item.toString() : item);
  
      // Combine the current whitelist with the ones to add
      const combined = [...currentWhitelistStr, ...addWhitelistStr];
      // Deduplicate by converting to a Set and back to an array
      const deduped = [...new Set(combined)];
      // Remove any items that are in the removeWhitelist
      const finalWhitelistStr = deduped.filter(id => !removeWhitelistStr.includes(id));
  
      // If you want to store ObjectIDs, convert them back:
      file.viewWhitelist = finalWhitelistStr.map(id => new mongoose.Types.ObjectId(id));
      file.isPrivate = true;
    }
  
    await file.save();
  };

  /*
const modifyFolderPermissions = async (isPrivate, folder, viewWhitelistAdd, viewWhitelistRemove, editWhitelistAdd, editWhitelistRemove, deleteWhitelistAdd, deleteWhitelistRemove) => {
    console.log("Inside helper function modifyFolderPermissions");
    if(!isPrivate) { // File is public
        folder.isPrivate = false;
        folder.viewWhitelist = null;
        folder.editWhitelist = null;
        folder.deleteWhitelist = null;
    }
    else {
        folder.viewWhitelist = [...new Set([...(folder.viewWhitelist || []), ...viewWhitelistAdd])];
        folder.viewWhitelist = folder.viewWhitelist.filter(item => !viewWhitelistRemove.includes(item));
        console.log(folder.viewWhitelist);
        console.log(viewWhitelistRemove);

        folder.editWhitelist = [...new Set([...(folder.editWhitelist || []), ...editWhitelistAdd])];
        folder.editWhitelist = folder.editWhitelist.filter(item => !editWhitelistRemove.includes(item));

        folder.deleteWhitelist = [...new Set([...(folder.deleteWhitelist || []), ...deleteWhitelistAdd])];
        folder.deleteWhitelist = folder.deleteWhitelist.filter(item => !deleteWhitelistRemove.includes(item));
    }

    await folder.save();

}
*/

const modifyFolderPermissions = async (isPrivate, folder, viewWhitelistAdd, viewWhitelistRemove, editWhitelistAdd, editWhitelistRemove, deleteWhitelistAdd, deleteWhitelistRemove) => {
    console.log("Inside helper function modifyFolderPermissions");

    if (!isPrivate) { 
        folder.isPrivate = false;
        folder.viewWhitelist = null;
        folder.editWhitelist = null;
        folder.deleteWhitelist = null;
    } else {
        // Process viewWhitelist:
        const currentView = (folder.viewWhitelist || []).map(id => id.toString());
        const viewAddStr = viewWhitelistAdd.map(item => item.toString());
        const viewRemoveStr = viewWhitelistRemove.map(item => item.toString());
        const viewCombined = [...new Set([...currentView, ...viewAddStr])];
        const finalView = viewCombined.filter(id => !viewRemoveStr.includes(id));
        folder.viewWhitelist = finalView.map(id => new mongoose.Types.ObjectId(id));

        // Process editWhitelist:
        const currentEdit = (folder.editWhitelist || []).map(id => id.toString());
        const editAddStr = editWhitelistAdd.map(item => item.toString());
        const editRemoveStr = editWhitelistRemove.map(item => item.toString());
        const editCombined = [...new Set([...currentEdit, ...editAddStr])];
        const finalEdit = editCombined.filter(id => !editRemoveStr.includes(id));
        folder.editWhitelist = finalEdit.map(id => new mongoose.Types.ObjectId(id));

        // Process deleteWhitelist:
        const currentDelete = (folder.deleteWhitelist || []).map(id => id.toString());
        const deleteAddStr = deleteWhitelistAdd.map(item => item.toString());
        const deleteRemoveStr = deleteWhitelistRemove.map(item => item.toString());
        const deleteCombined = [...new Set([...currentDelete, ...deleteAddStr])];
        const finalDelete = deleteCombined.filter(id => !deleteRemoveStr.includes(id));
        folder.deleteWhitelist = finalDelete.map(id => new mongoose.Types.ObjectId(id));

        folder.isPrivate = true;
    }
    await folder.save();
}







// Input: newPassword (prevalidated)
// Output: file.password will be modified
const modifyFilePassword = async (file, newPassword) => {
    newPassword = hashPassword(newPassword);
    file.password = newPassword;
    await file.save();
}

// Input: newPassword (prevalidated)
// Output: folder.password will be modified
const modifyFolderPassword = async (folder, newPassword) => {
    newPassword = hashPassword(newPassword);
    folder.password = newPassword;
    await folder.save();
}



module.exports = {hashPassword, deleteFile, renderFileView, renderHomepage, deleteFolder, renderFilePermissions, parseAndValidateList, modifyFilePermissions, modifyFilePassword, renderFolderPermissions, modifyFolderPassword, modifyFolderPermissions};