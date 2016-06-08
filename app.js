var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var expressSession = require('express-session');
var bcrypt = require('bcryptjs');
var mongoose = require('mongoose');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;

mongoose.connect('mongodb://localhost:27017/user_auth_1000');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));


app.use(expressSession({secret: 'wefnjo2uhuhefw0dshf2j3nfewoid'}));
app.use(passport.initialize());
app.use(passport.session());

var flash = require('connect-flash');
app.use(flash());

passport.serializeUser(function(user, done) {
        return done(null, user._id);
});

    // used to deserialize the user
passport.deserializeUser(function(id, done) {
      User.findById(id, function(err, user) {
          done(err, user);
      });
});

passport.use('signin', new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password',
  passReqToCallback: true
},
  function(req, email, password, done) {
    User.findOne({ email: email }, function (err, user) {
      if (err) { return done(err); }
      if (!user) { return done(null, false, req.flash('message', 'Email Not Found!')); }
      if (!user.verifyPassword(password)) { return done(null, false, req.flash('message', 'Invalid Password, try again!')); }
      return done(null, user);
    });
  }
));

passport.use('signup', new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: true
  },
  function(req, username, password, done) {

    User.findOne({ email: username }, function(err, user) {
      if (err) {
        return done(err);
      }

      if (user) {

        return done(null, false, req.flash('message', 'An Account With That Email Already Exists!'));

      } else {


          var hash = bcrypt.hashSync(password, bcrypt.genSaltSync(10));
          // Scramble it!

          var newUser = User({

            first_name: req.body.first_name,
            last_name: req.body.last_name,
            email: req.body.email,
            password: hash,
            country: req.body.country,
            state: req.body.state,
            city: req.body.city

          });

          newUser.save(function(err) {

            if (err) throw err;

            return done(null, newUser);

          });


      }

    });

  }
));

    // Require someone to be logged in
function requireLogin(req, res, next) {
    if (!req.isAuthenticated()) {
      res.redirect('/login');
    } else {
      next();
    }
}

var User = require('./models/user');


app.get('/', requireLogin, function(req, res) {

  res.locals.user = req.user;
  res.render('index', { title: 'User Auth 3000' });

});

app.get('/login', function(req ,res) {

  if (!req.isAuthenticated()) {
    res.render('login', { title: 'User Auth 3000', message: req.flash('message') });
  } else {
    res.redirect('/');
  }


});

app.post('/login', passport.authenticate('signin', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true 
}));




app.get('/signup', function(req, res) {

  if (!req.user) {
    res.render('signup', { title: 'User Auth 3000', message: req.flash('message') });
  } else {
    res.redirect('/');
  }

});

app.post('/signup', passport.authenticate('signup', {
  successRedirect: '/',
  failureRedirect: '/signup',
  failureFlash: true 
}));

app.get('/logout', function(req, res) {

  req.logout();
  res.redirect('/');

});

app.get('/edit', requireLogin, function(req, res) {

  res.locals.user = req.user;
  res.render('edit', { title: 'User Auth 3000' });

});

app.post('/edit', requireLogin, function(req, res) {

  var email = req.body.email;
  var password = req.body.password;

  // Find a matching user in mongo
  User.find({ email: email }, function(err, user) {
    if (err) res.redirect('/login');

    var foundUser = user[0];

    // Verify the existance of the user
    if (foundUser.length < 1) {

      res.redirect('/login');
      console.log("User Not Found");

    } else {
      
      if (bcrypt.compareSync(password, foundUser.password)) {

        // If there's a new password... if not re-hash the old one
        if (req.body.new_password.length > 1) {
          var hash = bcrypt.hashSync(req.body.new_password, bcrypt.genSaltSync(10));
        } else {
          var hash = bcrypt.hashSync(req.body.password, bcrypt.genSaltSync(10));
        }

        // Set the new account information
        foundUser.first_name = req.body.first_name
        foundUser.last_name = req.body.last_name
        foundUser.password = hash
        foundUser.country = req.body.country
        foundUser.state = req.body.state
        foundUser.city = req.body.city

        // Saves the user back to mongo
        foundUser.save(function(err) {          
          if (err) res.redirect('/edit');

          res.redirect('/');
          console.log("User Successfuly Updated");

        });

      } else {

        res.redirect('/edit');
        console.log("Incorrect Password");

      }

    }

  });

});

app.post('/delete', requireLogin, function(req, res) {

    var email = req.body.email;

    if (email === req.user.email) {

        User.find({ email: email }, function(err, user) {
          if (err) res.redirect('/edit');

          if (user.length > 0) {

              var foundUser = user[0];
              foundUser.remove(function(err) {

                  if (err) res.redirect('/edit');

                  req.logout();
                  res.redirect('/login');
                  console.log("User Successfuly Deleted!");

              });

          } else {
            res.redirect('/');
          }

        });
        
    }

});

app.get('/users', requireLogin, function(req, res) {

  User.find({}, function(err, users) {
      if (err) res.redirect('/');


      res.locals.users = users;
      res.locals.user = req.user;
      res.render('users', { title: 'User Auth 3000' });

  }); 

});



// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
  app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
      message: err.message,
      error: err
    });
  });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
  res.status(err.status || 500);
  res.render('error', {
    message: err.message,
    error: {}
  });
});


module.exports = app;
