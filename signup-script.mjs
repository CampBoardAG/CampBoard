document.getElementById("signupForm").addEventListener("submit", function(e) {
  e.preventDefault(); // Always prevent default first
  
  const username = document.getElementById("username").value;
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;
  const confirmPassword = document.getElementById("confirmPassword").value;
  const signupMessage = document.getElementById("signupMessage");
  
  // Reset message
  signupMessage.textContent = "";
  signupMessage.style.color = "";
  
  // Validate all fields are filled
  if (!username || !email || !password || !confirmPassword) {
    signupMessage.textContent = "Please fill in all fields.";
    signupMessage.style.color = "#ff6b6b";
    return false;
  }
  
  // Validate email format
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    signupMessage.textContent = "Please enter a valid email address.";
    signupMessage.style.color = "#ff6b6b";
    return false;
  }
  
  // Validate password match
  if (password !== confirmPassword) {
    signupMessage.textContent = "Passwords do not match.";
    signupMessage.style.color = "#ff6b6b";
    return false;
  }
  
  // Validate password strength
  if (!/(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}/.test(password)) {
    signupMessage.textContent = "Password must contain at least one number, one uppercase and lowercase letter, and be at least 8 characters long.";
    signupMessage.style.color = "#ff6b6b";
    return false;
  }
  
  // If all validations pass
  signupMessage.textContent = "Sign up successful "+ username +"! Redirecting...";
  signupMessage.style.color = "#00adb5";
  
  // Only redirect after successful validation
  setTimeout(() => {
    window.location.href = "data.html";
  }, 2000);
  
  return false; // Prevent form submission
});
