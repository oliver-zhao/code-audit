// Browser seeds: DOM XSS, jQuery, postMessage, Web Storage.
/* global $ */

function render(message) {
  document.getElementById("out").innerHTML = message;
  document.getElementById("title").innerHTML = decodeURIComponent(location.hash.slice(1));
  document.write("<p>" + document.referrer + "</p>");
  $("#greeting").html(message);
  $(window.location.hash);
  document.body.insertAdjacentHTML("beforeend", message);
}

window.addEventListener("message", (event) => {
  render(event.data);
});

function remember(token) {
  localStorage.setItem("authToken", token);
}

export { render, remember };
