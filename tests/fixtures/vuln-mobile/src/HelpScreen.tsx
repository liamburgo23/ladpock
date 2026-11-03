import { WebView } from "react-native-webview";

export function HelpScreen({ url }: { url: string }) {
  return <WebView source={{ uri: url }} originWhitelist={["*"]} allowFileAccess={true} />;
}
