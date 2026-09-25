const textarea = document.getElementById("whitelist");
const saveBtn = document.getElementById("save");
const savedLabel = document.getElementById("saved");

async function load() {
  const { whitelist } = await chrome.storage.sync.get(["whitelist"]);
  textarea.value = (whitelist || []).join("\n");
}

saveBtn.addEventListener("click", async () => {
  // Store bare hostnames (a pasted "https://example.com/login" becomes "example.com").
  const normalized = textarea.value.split("\n").map(self.HackDevLeakGuard.normalizeDomain).filter(Boolean);
  const whitelist = Array.from(new Set(normalized));
  await chrome.storage.sync.set({ whitelist });
  textarea.value = whitelist.join("\n");
  savedLabel.style.display = "inline";
  setTimeout(() => (savedLabel.style.display = "none"), 1500);
});

load();
