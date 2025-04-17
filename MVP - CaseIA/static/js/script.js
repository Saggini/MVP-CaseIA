document.getElementById("test-form").addEventListener("submit", function(e) {
    e.preventDefault();

    const criteria = document.getElementById("criteria").value;
    const systemType = document.getElementById("system_type").value;

    fetch('/generate_tests', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `criteria=${encodeURIComponent(criteria)}&system_type=${encodeURIComponent(systemType)}`
    })
    .then(response => response.json())
    .then(data => {
        const resultsDiv = document.getElementById("results");
        resultsDiv.innerHTML = "";

        if (data.error) {
            resultsDiv.innerHTML = `<p style="color: red;">${data.error}</p>`;
        } else {
            resultsDiv.innerHTML = `
                <h3>Casos de Teste Gerados:</h3>
                <pre>${data.test_cases}</pre>
            `;
        }
    })
    .catch(error => {
        const resultsDiv = document.getElementById("results");
        resultsDiv.innerHTML = `<p style="color: red;">Erro ao processar a solicitação: ${error.message}</p>`;
    });
});
