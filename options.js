const textarea = document.getElementById("whitelist");
const saveBtn = document.getElementById("save");
const savedLabel = document.getElementById("saved");

async function load() {
  const { whitelist } = await chrome.storage.sync.get(["whitelist"]);
  textarea.value = (whitelist || []).join("\n");
}

saveBtn.addEventListener("click", async () => {
  const whitelist = textarea.value
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
  await chrome.storage.sync.set({ whitelist });
  savedLabel.style.display = "inline";
  setTimeout(() => (savedLabel.style.display = "none"), 1500);
});

load();
