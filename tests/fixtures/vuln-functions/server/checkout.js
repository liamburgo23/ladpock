async function checkout(stripe) {
  return stripe.checkout.sessions.create({ success_url: `${origin}/thanks?paid=true`, line_items: [] });
}
module.exports = { checkout };
