// Safe counterparts of the browser seeds.
/* global $, DOMPurify */

function render(message) {
  document.getElementById("out").textContent = message;
  document.getElementById("title").textContent = decodeURIComponent(location.hash.slice(1));
  document.getElementById("rich").innerHTML = DOMPurify.sanitize(message);
  document.getElementById("empty").innerHTML = "";
  $("#greeting").text(message);
  $("#static").html("<b>Welcome</b>");
}

window.addEventListener("message", (event) => {
  if (event.origin !== "https://app.example.invalid") return;
  render(event.data);
});

function remember(theme) {
  localStorage.setItem("theme", theme);
}

export { render, remember };
