export function Admin() {
  if (localStorage.getItem("isAdmin") !== "true") return null;
  document.cookie = `authToken=${getToken()}; path=/`;
  return <div />;
}
