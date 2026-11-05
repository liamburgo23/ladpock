window.addEventListener("message", (event) => {
  if (event.origin !== "https://app.example.invalid") return;
  document.title = event.data.title;
});
