// login.mjs
document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  const messageElement = document.getElementById('loginMessage');
  
  // Clear previous messages
  messageElement.textContent = '';
  messageElement.className = '';
  
  // Basic validation
  if (!username || !password) {
      showMessage('Please enter both username and password', 'error');
      return;
  }
  
  try {
      const response = await fetch('/api/login', {
          method: 'POST',
          headers: {
              'Content-Type': 'application/json',
          },
          body: JSON.stringify({ username, password })
      });
      
      const data = await response.json();
      
      if (!response.ok) {
          throw new Error(data.message || 'Login failed');
      }
      
      showMessage('Login successful!', 'success');
      setTimeout(() => window.location.href = '/web/user1.html', 1500);
      
  } catch (error) {
      showMessage(error.message, 'error');
      console.error('Login error:', error);
  }
});

function showMessage(text, type) {
  const element = document.getElementById('loginMessage');
  element.textContent = text;
  element.className = type;
}
