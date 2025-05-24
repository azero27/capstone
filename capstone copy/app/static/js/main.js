function callAPI() {
    fetch('/api/test')
        .then(response => response.json())
        .then(data => {
            document.getElementById("result").innerText = data.message;
        })
        .catch(error => {
            console.error("API 호출 실패:", error);
        });
}
