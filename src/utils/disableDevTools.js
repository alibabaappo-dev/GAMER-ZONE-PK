// Disable Right Click
document.addEventListener("contextmenu", (e) => {
  e.preventDefault();
});

// Disable Keys
document.addEventListener("keydown", (e) => {
  // F12
  if (e.key === "F12") {
    e.preventDefault();
    return false;
  }

  // Ctrl+Shift+I / J / C
  if (e.ctrlKey && e.shiftKey && ["I", "J", "C"].includes(e.key.toUpperCase())) {
    e.preventDefault();
    return false;
  }

  // Ctrl+U (View Source)
  if (e.ctrlKey && e.key.toLowerCase() === "u") {
    e.preventDefault();
    e.stopPropagation();
    return false;
  }
});