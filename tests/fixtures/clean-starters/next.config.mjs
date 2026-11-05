/** @type {import("next").NextConfig} */
const config = {
  reactStrictMode: true,
  poweredByHeader: false,
  images: { remotePatterns: [{ protocol: "https", hostname: "avatars.githubusercontent.com" }] },
  async headers() {
    return [{ source: "/(.*)", headers: [
      { key: "Content-Security-Policy", value: "default-src 'self'" },
      { key: "X-Content-Type-Options", value: "nosniff" },
      { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
    ] }];
  },
};
export default config;
