export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api/feedback" && request.method === "POST") {
      await env.DB.prepare("INSERT INTO feedback (body) VALUES (?)").bind(await request.text()).run();
      return new Response("ok");
    }
    return new Response("not found", { status: 404 });
  },
};
