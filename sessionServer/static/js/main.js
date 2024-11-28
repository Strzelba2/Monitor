document.addEventListener("DOMContentLoaded", () => {
    const errorElement = document.querySelector("h1[data-error]"); 
    const errorMessage = errorElement.dataset.error; 

    const style = document.createElement("style");
    style.textContent = `
        h1::after {
            content: "${errorMessage}";
        }
    `;
    document.head.appendChild(style);
});