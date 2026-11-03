import AsyncStorage from "@react-native-async-storage/async-storage";

export async function saveSession(accessToken: string) {
  await AsyncStorage.setItem("accessToken", accessToken);
}
