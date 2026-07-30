const toggle = document.getElementById("enabledToggle");
const checkedEl = document.getElementById("checkedCount");
const breachedEl = document.getElementById("breachedCount");

async function refresh() {
  const { enabled } = await chrome.storage.sync.get(["enabled"]);
  toggle.checked = enabled !== false;

  const { stats } = await chrome.storage.local.get(["stats"]);
  const s = stats || { checked: 0, breached: 0 };
  checkedEl.textContent = s.checked || 0;
  breachedEl.textContent = s.breached || 0;
}

toggle.addEventListener("change", async () => {
  await chrome.storage.sync.set({ enabled: toggle.checked });
});

refresh();
