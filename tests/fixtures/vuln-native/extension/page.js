window.addEventListener("message", (event) => {
  document.title = event.data.title;
});
