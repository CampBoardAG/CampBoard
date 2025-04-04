document.getElementById("loginForm").addEventListener("submit", function(e) {
  e.preventDefault();
  
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;
  const message = document.getElementById("loginMessage");

  // Clear previous messages
  message.textContent = "";
  message.style.color = "";

  // Simple validation
  if (!email || !password) {
      showError("Please fill in all fields", message);
      return;
  }

  // Mock authentication
  if (email === "user@example.com" && password === "password123") {
      message.textContent = "Login successful! Redirecting...";
      message.style.color = "green";
      
      // REDIRECT CODE (100% working)
      setTimeout(() => {
          window.location.href = "dashboard.html"; // Make sure this file exists
      }, 1500); // 1.5 second delay to show message
  } else {
      showError("Invalid email or password", message);
  }
});

function showError(text, element) {
  element.textContent = text;
  element.style.color = "red";
}
