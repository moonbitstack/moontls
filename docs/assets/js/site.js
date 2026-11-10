// The page's own behaviour: the scrollbar's top state, and the theme, which follows the system
// until a reader chooses one and forgets that choice when the visit ends.

const root = document.documentElement;

const mark = () => root.classList.toggle("at-top", window.scrollY === 0);
window.addEventListener("scroll", mark, { passive: true });
mark();

const KEY = "moontls-theme";
const stored = sessionStorage.getItem(KEY);
if (stored === "light" || stored === "dark") root.dataset.theme = stored;

for (const button of document.querySelectorAll("[data-theme-toggle]")) {
  button.addEventListener("click", () => {
    const system = matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    const now = root.dataset.theme || system;
    const next = now === "dark" ? "light" : "dark";
    root.dataset.theme = next;
    sessionStorage.setItem(KEY, next);
    button.setAttribute("aria-label", next === "dark" ? "Switch to the light theme" : "Switch to the dark theme");
  });
}
