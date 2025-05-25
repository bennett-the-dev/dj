const express = require('express');
const session = require('express-session');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

app.use(express.static('public'));
app.use(express.json());
app.use(session({
  secret: 'your-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // true if using https
}));

// In-memory user store: { email: { username, email, passwordHash, verified, verifyToken, resetToken } }
const users = {};

// Setup your transporter (e.g. Gmail SMTP with app password)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'maxcrosby911@gmail.com',
    pass: 'ouow cope bvgg xjeq' // Use App Passwords if 2FA is enabled
  }
});;

// Signup route
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'Missing fields' });

  if (users[email]) return res.status(400).json({ error: 'User already exists' });

  const passwordHash = await bcrypt.hash(password, 10);
  const verifyToken = crypto.randomBytes(20).toString('hex');
  users[email] = { username, email, passwordHash, verified: false, verifyToken };

  // Send verification email
  try {
    await transporter.sendMail({
      from: `"Your App" <no-reply@${req.headers.host || 'localhost'}>`,
      to: email,
      subject: 'Verify your email',
      text: `Click here to verify your email: ${verifyLink}`
    });
    res.json({ success: true, message: 'Signup successful! Please check your email to verify your account.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to send verification email' });
  }
});

// Email verification route
app.get('/verify-email', (req, res) => {
  const { email, token } = req.query;
  const user = users[email];
  if (!user || user.verifyToken !== token) {
    return res.send('<h2>Invalid or expired verification link.</h2>');
  }
  user.verified = true;
  delete user.verifyToken;
  // Log the user in after verification
  req.session.user = { email: user.email, username: user.username };
  res.send(`<h2>Email verified! <a href="/">Go to Dashboard</a></h2>\n<script>setTimeout(()=>{window.location.href='/'},1500)</script>`);
});

// Login route (username or email + password)
app.post('/login', async (req, res) => {
  const { identifier, password } = req.body; // identifier = username or email
  if (!identifier || !password) return res.status(400).json({ error: 'Missing fields' });

  // Find user by email or username
  const user = Object.values(users).find(u => u.email === identifier || u.username === identifier);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) return res.status(401).json({ error: 'Invalid credentials' });

  if (!user.verified) return res.status(403).json({ error: 'Please verify your email before logging in.' });

  req.session.user = { email: user.email, username: user.username };
  res.json({ success: true });
});

// Forgot password - send reset link
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });

  const user = users[email];
  if (!user) return res.status(400).json({ error: 'No user with that email' });

  // Create reset token and store it
  const resetToken = crypto.randomBytes(20).toString('hex');
  user.resetToken = resetToken;

  const baseUrl = req.headers.origin || `http://${req.headers.host}` || `http://localhost:${PORT}`;
  const resetLink = `${baseUrl}/reset-password.html?token=${resetToken}&email=${encodeURIComponent(email)}`;

  // Send password reset email
  try {
    await transporter.sendMail({
      from: `"Your App" <no-reply@${req.headers.host || 'localhost'}>`,
      to: email,
      subject: 'Password Reset Link',
      text: `Click here to reset your password: ${resetLink}`
    });
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to send email' });
  }
});

// Serve reset-password.html page (create this page in /public)
// You should handle GET /reset-password.html?token=...&email=...

// Reset password route
app.post('/reset-password', async (req, res) => {
  const { email, token, newPassword } = req.body;
  if (!email || !token || !newPassword) return res.status(400).json({ error: 'Missing fields' });

  const user = users[email];
  if (!user || user.resetToken !== token) return res.status(400).json({ error: 'Invalid token' });

  user.passwordHash = await bcrypt.hash(newPassword, 10);
  delete user.resetToken;

  res.json({ success: true });
});

// Check if logged in
app.get('/me', (req, res) => {
  if (req.session.user) {
    const user = users[req.session.user.email];
    if (user && user.verified) {
      return res.json({ loggedIn: true, user: req.session.user });
    }
    // Not verified
    return res.json({ loggedIn: false, notVerified: true });
  }
  res.json({ loggedIn: false });
});

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
