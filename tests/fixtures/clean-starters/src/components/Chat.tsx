"use client";
import { useChat } from "ai/react";

export function Chat() {
  const { messages, input, handleInputChange, handleSubmit } = useChat();
  return (
    <form onSubmit={handleSubmit}>
      {messages.map((message) => <p key={message.id}>{message.content}</p>)}
      <input value={input} onChange={handleInputChange} />
    </form>
  );
}
