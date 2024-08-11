// Import necessary modules
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

// Define the user schema
const userSchema = new mongoose.Schema({
    firstName: {
        type: String,
        required: true,
    },
    lastName: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
    },
    password: {
        type: String,
        required: true,
    },
    isAdmin: {
        type: Boolean,
        default: false,
    },
    passwordHistory: [String],  // Store hashed previous passwords

    failedLoginAttempts: {
        type: Number,
        default: 0,
    },
    lastFailedLogin: {
        type: Date,
        default: null,
    },
    passwordLastChanged: {  // Track the last password change date
        type: Date,
        default: Date.now,
    },
});

// Password hashing before saving the user hasing 
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();

    // Hash the new password
    const hash = await bcrypt.hash(this.password, 10);

    // Add current hashed password to password history
    this.passwordHistory.push(hash);

    // Update the password with the hashed version
    this.password = hash;

    // Update the passwordLastChanged date
    this.passwordLastChanged = Date.now();

    // Limit the password history to the last 5 passwords
    if (this.passwordHistory.length > 5) {
        this.passwordHistory.shift();
    }

    next();
});

// Method to compare passwords during login
userSchema.methods.comparePassword = async function (candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
};

// Method to check if a password is reused from history
userSchema.methods.isPasswordReused = async function (newPassword) {
    for (const oldPassword of this.passwordHistory) {
        if (await bcrypt.compare(newPassword, oldPassword)) {
            return true;
        }
    }
    return false;
};

// Account lockout mechanism
userSchema.methods.incrementLoginAttempts = function (callback) {
    const lockoutTime = 1 * 60 * 60 * 1000; // 1 hour lockout time

    // Check if account is already locked
    if (this.lastFailedLogin && this.lastFailedLogin > Date.now() - lockoutTime) {
        this.failedLoginAttempts += 1;
    } else {
        this.failedLoginAttempts = 1; // Reset failed attempts if outside lockout window
    }

    // If failed attempts exceed 5, lock the account
    if (this.failedLoginAttempts >= 5) {
        this.lastFailedLogin = Date.now();
    }

    this.save(callback);
};

const User = mongoose.model('users', userSchema);

module.exports = User;
