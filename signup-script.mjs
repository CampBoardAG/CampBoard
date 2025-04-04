const signupForm = document.getElementById("signupForm");
const signupMessage = document.getElementById("signupMessage");

signupForm.addEventListener("submit", (e) => {
  e.preventDefault();

  const username = document.getElementById("username").value;
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;
  const confirmPassword = document.getElementById("confirmPassword").value;

  // Basic form validation
  if (password !== confirmPassword) {
    signupMessage.textContent = "Passwords do not match.";
    signupMessage.style.color = "#ff6b6b";
    return;
  }

  // This is a mock signup process. In a real application, you would send this data to a backend.
  if (username && email && password) {
    signupMessage.textContent =
      "Sign up successful! Welcome, " + username + "!";
    signupMessage.style.color = "#00adb5";
    // Here you would typically send the data to a server and handle the response
  } else {
    signupMessage.textContent = "Please fill in all fields.";
    signupMessage.style.color = "#ff6b6b";
  }
});
