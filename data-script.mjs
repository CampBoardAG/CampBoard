document.addEventListener('DOMContentLoaded', () => {
  const submitBtn = document.getElementById('submitData');
  const formMessage = document.getElementById('formMessage');

  submitBtn.addEventListener('click', () => {
      const name = document.getElementById('studentName').value;
      const email = document.getElementById('studentEmail').value;

      // Clear previous messages
      formMessage.textContent = '';
      formMessage.style.color = '';

      // Validate inputs
      if (!name || !email) {
          showError('Please fill all fields', formMessage);
          return;
      }

      // Process data (replace with actual submission logic)
      console.log('Submitting:', { name, email });
      formMessage.textContent = 'Data submitted successfully!';
      formMessage.style.color = 'green';

      // Optional: Clear form after submission
      document.getElementById('dataForm').reset();
  });

  function showError(message, element) {
      element.textContent = message;
      element.style.color = 'red';
      element.classList.add('shake');
      setTimeout(() => element.classList.remove('shake'), 500);
  }
});
