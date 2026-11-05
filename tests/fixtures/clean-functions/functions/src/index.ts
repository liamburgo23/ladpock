import { onCall } from "firebase-functions/v2/https";
import { getFirestore } from "firebase-admin/firestore";

const db = getFirestore();

export const deleteAccount = onCall(async (request) => {
  if (!request.auth) throw new Error("no");
  await db.collection("users").doc(request.auth.uid).delete();
});
