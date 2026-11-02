"use client";

import { useEffect, useState } from "react";

export function Orders() {
  const [orders, setOrders] = useState<{ id: string }[]>([]);

  useEffect(() => {
    fetch("/api/orders").then((r) => r.json()).then(setOrders);
  }, []);

  useEffect(() => {
    const timer = setInterval(() => {
      fetch("/api/orders").then((r) => r.json()).then(setOrders);
    }, 30_000);
    return () => clearInterval(timer);
  }, []);

  const requestId = crypto.randomUUID();

  return (
    <ul data-request={requestId}>
      {orders.map((o) => (
        <li key={o.id}>{o.id}</li>
      ))}
    </ul>
  );
}
