async function checkout(stripe) {
  return stripe.checkout.sessions.create({ success_url: `${origin}/thanks?session_id={CHECKOUT_SESSION_ID}`, line_items: [] });
}
module.exports = { checkout };
