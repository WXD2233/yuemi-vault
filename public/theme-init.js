try {
  const saved = localStorage.getItem("yuemi-theme") || "system";
  const themes = ["dark", "light", "violet", "glacier", "amber", "system"];
  const preference = themes.includes(saved) ? saved : "system";
  const resolved =
    preference === "system"
      ? matchMedia("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light"
      : preference;
  document.documentElement.dataset.theme = resolved;
  document.documentElement.dataset.themePreference = preference;
  document.documentElement.style.colorScheme =
    resolved === "light" || resolved === "glacier" ? "light" : "dark";
} catch {
  document.documentElement.dataset.theme = "dark";
}
