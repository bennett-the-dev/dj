async function signup() {
  const username = document.getElementById('su-username').value.trim();
  const email = document.getElementById('su-email').value.trim();
  const password = document.getElementById('su-password').value;

  if (!username || !email || !password) {
    alert('Please fill all signup fields.');
    return;
  }

  const res = await fetch('/signup', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ username, email, password })
  });
  const data = await res.json();

  if (data.success) {
    alert('Signup successful!');
    loadUser();
  } else {
    alert(data.error || 'Signup failed');
  }
}

async function login() {
  const identifier = document.getElementById('li-identifier').value.trim();
  const password = document.getElementById('li-password').value;

  if (!identifier || !password) {
    alert('Please fill all login fields.');
    return;
  }

  const res = await fetch('/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ identifier, password })
  });
  const data = await res.json();

  if (data.success) {
    alert('Logged in!');
    loadUser();
  } else {
    alert(data.error || 'Login failed');
  }
}

async function forgotPassword() {
  const email = document.getElementById('fp-email').value.trim();

  if (!email) {
    alert('Please enter your email.');
    return;
  }

  const res = await fetch('/forgot-password', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ email })
  });
  const data = await res.json();

  alert(data.message || 'If your email exists, you will receive a reset link.');
}

async function logout() {
  await fetch('/logout', { method: 'POST' });
  loadUser();
}

async function loadUser() {
  const res = await fetch('/me');
  const data = await res.json();

  if (data.loggedIn) {
    document.getElementById('login').style.display = 'none';
    document.getElementById('signup').style.display = 'none';
    document.getElementById('forgot').style.display = 'none';

    document.getElementById('dashboard').style.display = 'block';
    document.getElementById('username').textContent = data.user.username;
    document.getElementById('useremail').textContent = data.user.email;
  } else {
    document.getElementById('login').style.display = 'block';
    document.getElementById('signup').style.display = 'block';
    document.getElementById('forgot').style.display = 'block';

    document.getElementById('dashboard').style.display = 'none';
  }
}

window.onload = loadUser;
