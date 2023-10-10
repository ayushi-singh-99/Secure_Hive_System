const express = require("express");
const dotenv = require("dotenv");
const morgan = require("morgan");
const path = require("path");
const expressLayouts = require('express-ejs-layouts');
const flash = require('connect-flash');
const methodOverride = require("method-override");
const passport = require("passport");
const session = require("express-session");
const MongoStore = require("connect-mongo");

// DATABASE CONNECTION
const connectDB = require("./config/db");
const { connection } = require("mongoose");

// Load config
dotenv.config({ path: "./config/config.env" });

//Passport config
require("./config/passport")(passport);

connectDB();

const app = express();

// Body Parser
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Method Override
app.use(
  methodOverride((req, res) => {
    if (req.body && typeof req.body === "object" && "_method" in req.body) {
      let method = req.body._method;
      delete req.body._method;
      return method;
    }
  })
);

// EJS Configuration
app.use(express.static('public'))
app.use('/css', express.static(__dirname + 'public/css'))
app.use(expressLayouts)
app.set('layout', './layouts/main')
app.set('view engine', 'ejs')

// Express Session Middleware
app.use(
  session({
    secret: process.env.SECRET_KEY,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI,
      collection: "sessions",
    }),
    cookie: {
      maxAge: 1000 * 60 * 60 * 24, // 1 Day
    },
  })
);

// Passport Middleware
app.use(passport.initialize());
app.use(passport.session());

// Connecting Flash
app.use(flash());

// Global Variables
app.use(function(req, res, next) {
  res.locals.success_msg = req.flash('success_msg');
  res.locals.error_msg = req.flash('error_msg');
  res.locals.error = req.flash('error');
  next();
});

// Routes
app.use("/", require("./routes/index"));
app.use("/auth", require("./routes/auth"));
app.use("/files", require("./routes/files"));
app.use("/admin", require("./routes/admin"));

if (process.env.NODE_ENV === "development") {
  app.use(morgan('dev'));
}

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running in ${process.env.NODE_ENV} mode on PORT ${PORT}`);
});
