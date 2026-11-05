import { defineConfig } from "vite";

export default defineConfig({ define: { "import.meta.env.VITE_APP_NAME": JSON.stringify("demo") } });
