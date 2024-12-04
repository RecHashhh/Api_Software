document.getElementById('newUserForm').addEventListener('submit', async function(event) {
    event.preventDefault(); // Evita que se recargue la página

    const username = document.getElementById('username').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    const token = localStorage.getItem('jwt_token'); // Obtiene el token del localStorage

    const response = await fetch('/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`, // Incluye el token en la cabecera
        },
        body: JSON.stringify({
            username,
            email,
            password
        })
    });

    const result = await response.json();
    document.getElementById('message').textContent = result.message; // Muestra el mensaje en la página

    if (response.ok) {
        // Reinicia el formulario si el registro fue exitoso
        document.getElementById('newUserForm').reset();
    }
});
