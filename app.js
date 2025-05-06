import "dotenv/config";
import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import * as argon2 from "argon2";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import axios from "axios";
import flash from "connect-flash";

const app = express();
const port = 3000;

// Connect to PostgreSQL database.
// const db = new pg.Client({
//   user: process.env.USER,
//   host: process.env.HOST,
//   database: process.env.DATABASE,
//   password: process.env.PASSWORD,
//   port: process.env.PORT,
// });

// Connect to Render PostgreSQL server.
const db = new pg.Client({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});
db.connect();

// Middleware.
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

// Session middleware setup.
app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

app.use(flash());

// Passport initialization.
app.use(passport.initialize());
app.use(passport.session());

// Passport serialize/deserialize
passport.serializeUser((user, done) => {
  done(null, user.id);
});
passport.deserializeUser(async (id, done) => {
  const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
  done(null, result.rows[0]);
});

// Make flash messages available to all EJS templates.
app.use((req, res, next) => {
  res.locals.error = req.flash("error");
  res.locals.success = req.flash("success");
  next();
});

// Google Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const result = await db.query(
          "SELECT * FROM users WHERE google_id = $1",
          [profile.id]
        );

        let user;
        if (result.rows.length > 0) {
          user = result.rows[0];
        } else {
          const insert = await db.query(
            "INSERT INTO users (email, google_id) VALUES ($1, $2) RETURNING *",
            [profile.emails[0].value, profile.id]
          );
          user = insert.rows[0];
        }
        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  )
);

// Home route.
app.get("/", (req, res) => {
  res.render("home");
});

// Get register page.
app.get("/register", (req, res) => {
  res.render("register");
});

// Register route.
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  try {
    // Hashing the password with Argon2id.
    const hash = await argon2.hash(password, {
      type: argon2.argon2id,
      secret: Buffer.from(process.env.SECRET, "utf-8"),
      memoryCost: 2 ** 16, // 64MB memory
      timeCost: 3,
      parallelism: 1,
    });

    // Save the user to the database.
    let result;
    try {
      result = await db.query(
        "INSERT INTO users (email, password) VALUES($1, $2) RETURNING *;",
        [username, hash]
      );
    } catch (error) {
      if (error.code === "23505") {
        req.flash("error", "Email already registered.");
        return res.redirect("/register");
      }
      throw error;
    }

    // Regenerate the session before logging in the user.
    req.session.regenerate((err) => {
      if (err) {
        console.error("Session regeneration failed:", err);
        req.flash("error", "Session error during registration.");
        return res.redirect("/register");
      }

      // Now, log in the user after the session is regenerated.
      req.login(result.rows[0], (err) => {
        if (err) {
          console.error("Login after registration failed:", err);
          req.flash("error", "Auto-login failed after registration!");
          return res.redirect("/login");
        }

        // Redirect to the secrets page after successful login
        res.redirect("/secrets");
      });
    });
  } catch (error) {
    console.error("Error during registration:", error);
    req.flash("error", "Registration failed.");
    res.redirect("/register");
  }
});

// Get login page.
app.get("/login", (req, res) => {
  res.render("login");
});

// Login route.
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    // Fetch the user's hashed password from the database.
    const result = await db.query("SELECT * FROM users where email = $1;", [
      username,
    ]);

    if (result.rows.length === 0) {
      req.flash("error", "User not found!");
      return res.redirect("/login");
    }

    const storedHash = result.rows[0].password;

    // Verify the password against the stored hash.
    const isValid = await argon2.verify(storedHash, password, {
      secret: Buffer.from(process.env.SECRET, "utf-8"),
    });

    if (isValid) {
      // Regenerate the session before logging the user in.
      req.session.regenerate((err) => {
        if (err) {
          console.error("Login session setup failed!:", err);
          req.flash("error", "Login session setup failed!");
          return res.redirect("/login");
        }

        // Log in the user after session regeneration.
        req.login(result.rows[0], (err) => {
          if (err) {
            console.error("Login session setup failed:", err);
            req.flash("error", "Login session setup failed!");
            return res.redirect("/login");
          }

          // Redirect to the secrets page after successful login
          res.redirect("/secrets");
        });
      });
    } else {
      req.flash("error", "Incorrect password! Try again.");
      return res.redirect("/login");
    }
  } catch (error) {
    console.log("Error during login:", error);
    req.flash("error", "Login failed!");
    res.redirect("/login");
  }
});

// Google OAuth routes.
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    res.redirect("/secrets");
  }
);

// Get secrets page (only accessible after login).
app.get("/secrets", async (req, res) => {
  const userId = req.user?.id;

  if (!userId) {
    return res.redirect("/login");
  }

  try {
    // Fetch random secret from external API.
    const apiRespose = await axios.get(
      "https://secrets-api.appbrewery.com/random"
    );
    const randomSecret = apiRespose.data.secret;

    // Fetch all user-submitted secrets from the database.
    const allSecretsResult = await db.query(
      "SELECT content FROM secrets WHERE user_id != $1",
      [userId]
    );

    // Fetch secrets from the current user.
    const userSecretsResult = await db.query(
      "SELECT content FROM secrets WHERE user_id = $1",
      [userId]
    );

    res.render("secrets", {
      secret: allSecretsResult.rows.map((row) => row.content),
      userSecret: userSecretsResult.rows.map((row) => row.content),
      randomSecret,
    });
  } catch (error) {
    console.error("Error fetching secrets:", error);
    req.flash("error", "Failed to load secrets!");
    res.redirect("/secrets");
  }
});

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/login");
}

// Submit route.
app.get("/submit", ensureAuthenticated, (req, res) => {
  res.render("submit");
});

// Submit the secrets.
app.post("/submit", async (req, res) => {
  const submittedSecret = req.body.secret?.trim();
  const userId = req.user?.id;

  try {
    const userCheck = await db.query("SELECT * FROM users WHERE id = $1", [
      userId,
    ]);

    if (userCheck.rows.length === 0) {
      console.log("User not found.");
      req.flash("error", "User not found!");
      return res.redirect("/login");
    }

    // Insert the new secret into the 'secrets' table.
    await db.query("INSERT INTO secrets (user_id, content) VALUES ($1, $2)", [
      userId,
      submittedSecret,
    ]);

    req.flash("success", "Your secret has been submitted successfully!");
    res.redirect("/secrets");
  } catch (error) {
    console.error("Error submitting secret:", error);
    req.flash("error", "Failed to submit secret!");
    res.redirect("/secrets");
  }
});

// Logout route.
app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) return req.flash("error", "Logout failed!");
    req.session.destroy(() => {
      res.redirect("/");
    });
  });
});

// Start the server.
app.listen(port, () => {
  console.log(`Server running at port: ${port}`);
});
