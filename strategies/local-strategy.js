const passport = require("passport");
const Strategy = require("passport-local");
const mongoose = require("mongoose"); // Will use MongoDB to store user data
const User = require('../models/User.js');


passport.serializeUser((user, done) => { // Take user, return ID
    done(null, user.id); // user.id is automatically added to users by mongoose/MongoDB
});


passport.deserializeUser(async (userID, done) => { // Take ID, return user
    try {
        const findUser = await User.findById(userID); // Find user with given ID in MongoDB database

        if(!findUser) throw new Error("User not found");
        done(null, findUser);
    } catch(err) {
        done(err, null); //Pass error, user was not found for given ID
    }
})





module.exports = passport.use( 
    new Strategy(async (username, password, done) => {
        try {
            // Attempt to find user via given username, will return null if none found
            const findUser = await User.findOne({username: username}); // asynchronous access
            if(!findUser) throw new Error("No user by that username");
            if(findUser.password != password) throw new Error("Incorrect password"); //TODO Add bcrypt for hashing passwords


            done(null, findUser); // Attach user to session for easy access
            
        } catch (err) {
            done(err); // Invalid attempt, return err.
        }
    })
);