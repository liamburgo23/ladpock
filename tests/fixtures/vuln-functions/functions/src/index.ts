import * as functions from "firebase-functions";
import { onCall, onRequest } from "firebase-functions/v2/https";
import { getFirestore } from "firebase-admin/firestore";

const db = getFirestore();

exports.deleteAccount = functions.https.onCall(async (data) => {
  await db.collection("users").doc(data.userId).delete();
});

export const readProfile = onCall(async (request) => {
  if (!request.auth) throw new Error("no");
  return db.collection("profiles").doc(request.data.profileId).get();
});

export const addComment = onRequest(async (req, res) => {
  await db.collection("comments").add(req.body);
  res.send("ok");
});
