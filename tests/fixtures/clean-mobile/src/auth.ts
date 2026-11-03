import * as SecureStore from "expo-secure-store";

export async function saveSession(accessToken: string) {
  await SecureStore.setItemAsync("accessToken", accessToken);
}
