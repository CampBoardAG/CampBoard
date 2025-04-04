function clearErrors() {
    const errorElements = document.querySelectorAll('.error-message');
    errorElements.forEach(el => el.remove());
}

function showError(inputElement, message) {
    const errorElement = document.createElement('div');
    errorElement.className = 'error-message';
    errorElement.textContent = message;
    inputElement.parentNode.insertBefore(errorElement, inputElement.nextSibling);
    inputElement.focus();
}

function validateForm() {
    let isValid = true;
    
    // Personal Details Validation
    const name = document.getElementById('name');
    if (!name.value.trim()) {
        showError(name, 'Please enter your full name');
        isValid = false;
    }
    
    const age = document.getElementById('age');
    if (age.value < 16 || age.value > 100) {
        showError(age, 'Age must be between 16 and 100');
        isValid = false;
    }
    
    const contact = document.getElementById('contact-number');
    if (!/^\d{10}$/.test(contact.value)) {
        showError(contact, 'Please enter a valid 10-digit phone number');
        isValid = false;
    }
    
    const email = document.getElementById('email');
    if (!/^[^\\s@]+@[^\\s@]+\.[^\\s@]+$/.test(email.value)) {
        showError(email, 'Please enter a valid email address');
        isValid = false;
    }
    
    const idType = document.getElementById('government-id').value;
    const idNumber = document.getElementById('id-number');
    
    if (idType === 'aadhar' && !/^\d{12}$/.test(idNumber.value)) {
        showError(idNumber, 'Aadhar number must be 12 digits');
        isValid = false;
    } else if (idType === 'passport' && !/^[A-Z][0-9]{7}$/.test(idNumber.value)) {
        showError(idNumber, 'Passport number format invalid (e.g., A1234567)');
        isValid = false;
    } else if (idType === 'voter-id' && !/^[A-Z]{3}[0-9]{7}$/.test(idNumber.value)) {
        showError(idNumber, 'Voter ID format invalid (e.g., ABC1234567)');
        isValid = false;
    }
    
    const pincode = document.getElementById('pincode');
    if (!/^\d{6}$/.test(pincode.value)) {
        showError(pincode, 'Pin code must be 6 digits');
        isValid = false;
    }
    
    // Exam Center Validation
    for (let i = 1; i <= 5; i++) {
        const center = document.getElementById(`exam-center-${i}`);
        if (!center.value.trim()) {
            showError(center, `Exam center preference ${i} is required`);
            isValid = false;
        }
    }
    
    // File Upload Validation
    const requiredFiles = [
        'passport-photo',
        'signature',
        '10th-marksheet',
        '12th-marksheet',
        'adhar-copy'
    ];
    
    requiredFiles.forEach(id => {
        const fileInput = document.getElementById(id);
        if (fileInput.files.length === 0) {
            showError(fileInput, 'This file is required');
            isValid = false;
        } else {
            const file = fileInput.files[0];
            const validImageTypes = ['image/jpeg', 'image/png'];
            const validDocTypes = ['application/pdf', ...validImageTypes];
            
            if (file.size > 2 * 1024 * 1024) {
                showError(fileInput, 'File size must be less than 2MB');
                isValid = false;
            }
            
            if ((id === 'passport-photo' || id === 'signature') && 
                !validImageTypes.includes(file.type)) {
                showError(fileInput, 'Only JPEG or PNG images allowed');
                isValid = false;
            } else if (!validDocTypes.includes(file.type)) {
                showError(fileInput, 'Only PDF, JPEG, or PNG files allowed');
                isValid = false;
            }
        }
    });
    
    return isValid;
}

export { validateForm };
