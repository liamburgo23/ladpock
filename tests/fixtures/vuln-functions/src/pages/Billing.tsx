export function Billing() {
  const upgraded = new URLSearchParams(location.search).get("upgraded");
  return upgraded ? <Pro /> : <Free />;
}
