"use client";

import { useEffect, useState } from "react";
import { createClient } from "@supabase/supabase-js";

const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

export default function Dashboard({ bio }: { bio: string }) {
  const [orders, setOrders] = useState([]);

  useEffect(() => {
    fetch("/api/orders").then((r) => r.json()).then(setOrders);
  });

  useEffect(() => {
    const timer = setInterval(() => {
      fetch("/api/notifications");
    }, 500);
    return () => clearInterval(timer);
  }, []);

  function login(token: string) {
    localStorage.setItem("authToken", token);
  }

  const inviteCode = Math.random().toString(36).slice(2);

  return (
    <div>
      <div dangerouslySetInnerHTML={{ __html: bio }} />
      <p>Invite code: {inviteCode}</p>
    </div>
  );
}
