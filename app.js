//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

console.log(process.env.API_KEY);


app.set("view engine","ejs");

app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

app.use(session({
  secret:"This is our little secret.",
  resave : false,
  saveUninitialized: true,
}));

app.use(passport.initialize());
app.use(passport.session());

// Database connection and schema creation

mongoose.connect("mongodb://localhost:27017/secret",{useNewUrlParser:true ,useUnifiedTopology: true});
mongoose.set("useCreateIndex", true);
const userSchema =new mongoose.Schema({
  email :String,
  password : String,
  googleId : String,
  secret :String
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
//encryption create it before mongoose model


const User = new  mongoose.model("User",userSchema);
passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});
//oauth
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL :"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


// Handling Get Routes
app.get("/",function(req,res){
  res.render("home");
});

app.get("/login",function(req,res){
  res.render("login");
});

app.get("/register",function(req,res){
  res.render("register");
});

app.get("/logout",function(req,res){
   req.logout();
  res.redirect("/");
});

app.get("/submit", function(req,res){
  if(req.isAuthenticated()){
     res.render("submit");
  }else{
    res.redirect("/login");
  }
});

// this will make secure

// app.get("/secrets", function(req,res){
//   if(req.isAuthenticated()){
//      res.render("secrets");
//   }else{
//     res.redirect("/login");
//   }
// });

// making secret page public

app.get("/secrets",function(req,res){
  User.find({secret:{$ne :null}},function(err,foundUser){
    if(err){
      console.log(err);
    }else{
      if(foundUser){
        res.render("secrets",{userWithSecrets : foundUser});
      }
    }
  });
});

app.get("/logout",function(req,res){
  req.logout();
  res.redirect("/");
});

app.get("/auth/google",passport.authenticate('google', { scope: ['profile'] }));

app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });




// handling post request

app.post("/register",function(req,res){
  User.register({username :req.body.username},req.body.password,function(err,user){
    if(err){
      console.log(err);
      res.redirect("/register");
    }else{
      passport.authenticate("local")(req,res,function(){
        res.render("secrets");
      });
    }
  });

});

app.post("/login",function(req,res){
  const user = new User({
    username : req.body.username,
    password : req.body.password
  });
  req.login(user,function(err){
    if(err){
      console.log(err);
    }else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/submit",function(req,res){
  const submittedSecret = req.body.secret;
  User.findById(req.user._id,function(err,foundUser){
    if(err){
      console.log(err);
    }else{
      if(foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(err){
          if(err){
            console.log(err);
          }else{
            res.redirect("/secrets");
          }
        });
      }
    }
  });
});





// server creation
app.listen(3000,function(){
  console.log("Server started at 3000");
})
