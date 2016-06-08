var bcrypt = require('bcryptjs');
var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var userSchema = new Schema({

	first_name: String,
	last_name: String,
	email: { type: String, required: true, unique: true },
	password: { type: String, required: true },
	country: String,
	state: String,
	city: String,
	created_at: Date,
	updated_at: Date

});

userSchema.pre('save', function(next) {
	
	var current_date = new Date();

	this.updated_at = current_date;

	if (!this.created_at) {
		this.created_at = current_date;
	}

	next();

});

userSchema.methods.verifyPassword = function(password) {
    return bcrypt.compareSync(password, this.password);
};

var User = mongoose.model('User', userSchema);

module.exports = User;