var assert = require('chai').assert;
var User = require('../models/user');

var newUser = User({
	first_name: 'Julian',
	last_name: 'Guterman',
	email: 'gutermanj@gmail.com',
	password: 'mysupersecretpassword',
	country: 'US',
	state: 'Florida',
	city: 'Boynton Beach'
});


describe('Array', function() {
  describe('#indexOf()', function () {
    it('should return -1 when the value is not present', function () {
      assert.equal(-1, [1,2,3].indexOf(5));
      assert.equal(-1, [1,2,3].indexOf(0));
    });
  });
});

describe('newUser', function() {
	describe('#save()', function() {

		it('should add a user to mongodb', function() {

		});

	});
});