function populateTable() {
    const tableBody = document.querySelector("#userTable tbody");
    userData.forEach((user) => {
      const row = document.createElement("tr");
      row.innerHTML = `
              <td>${user.id}</td>
              <td>${user.name}</td>
              <td>${user.email}</td>
          `;
      tableBody.appendChild(row);
    });
  }
  fetch('/api/stats')
    .then(response => response.json())
    .then(data => {
        document.getElementById('stats').innerHTML = `
            <p>Students: ${data.students}</p>
            <p>Courses: ${data.courses}</p>
        `;
    });
  document.addEventListener("DOMContentLoaded", populateTable);
  
