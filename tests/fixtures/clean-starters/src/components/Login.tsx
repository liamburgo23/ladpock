"use client";
import { useState } from "react";
import { signIn } from "next-auth/react";

export function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const submit = async () => {
    const result = await signIn("credentials", { email, password, redirect: false });
    if (result?.error) console.log("Invalid email or password");
    localStorage.setItem("lastEmail", email);
    localStorage.getItem("theme");
  };
  return <form onSubmit={submit}><input type="email" value={email} onChange={(e) => setEmail(e.target.value)} /><input type="password" value={password} onChange={(e) => setPassword(e.target.value)} /></form>;
}
