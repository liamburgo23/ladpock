import { onCall, HttpsError } from "firebase-functions/v2/https";
import { getFirestore } from "firebase-admin/firestore";

const db = getFirestore();

export const addNote = onCall(async (request) => {
  if (!request.auth) throw new HttpsError("unauthenticated", "Sign in first");
  await db.collection("users").doc(request.auth.uid).collection("notes").add({ text: String(request.data.text) });
});
