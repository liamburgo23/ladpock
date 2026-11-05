chrome.runtime.onMessageExternal.addListener((message, sender, reply) => {
  chrome.storage.local.set({ settings: message.settings });
});
