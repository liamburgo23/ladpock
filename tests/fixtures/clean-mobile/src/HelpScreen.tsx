import { WebView } from "react-native-webview";

export function HelpScreen() {
  return <WebView source={{ uri: "https://help.example.dev" }} originWhitelist={["https://help.example.dev"]} />;
}
