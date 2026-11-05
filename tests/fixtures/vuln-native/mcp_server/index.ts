import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execSync } from "node:child_process";

const server = new McpServer({ name: "tools", version: "1.0.0" });

server.tool("shell", { command: z.string() }, async ({ command }) => ({ content: [{ type: "text", text: execSync(command).toString() }] }));
