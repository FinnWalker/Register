  
const mongoose = require('mongoose');
const uniqueValidator = require('mongoose-unique-validator');
const bcrypt = require('bcrypt');
const saltRounds = 10;

const Schema = mongoose.Schema;

const UserSchema = new Schema({
    email: {
        type: String,
        trim: true,
        required: true,
        unique: true
    },
    password: {
        type: String,
        trim: true,
        required: true
    },
    active: {
        type: Boolean,
        required: true
    },
    verification_token: {
        type: String,
        required: true
    }
});

// Hash user password before saving into database
UserSchema.pre('save', function(next) {
    const user = this;
    if (!user.isModified('password')) return next();

    this.password = bcrypt.hashSync(this.password, saltRounds);
    next();
});

UserSchema.plugin(uniqueValidator);

module.exports = mongoose.model('User', UserSchema);