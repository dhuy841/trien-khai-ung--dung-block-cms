(() => {
  document.querySelectorAll("[data-password-toggle]").forEach((button) => {
    button.addEventListener("click", () => {
      const input = button.closest(".password-input-wrap")?.querySelector("input");
      if (!input) return;

      const showing = input.type === "password";
      input.type = showing ? "text" : "password";
      button.setAttribute("aria-pressed", String(showing));
      button.setAttribute("aria-label", showing ? "Ẩn mật khẩu" : "Hiện mật khẩu");
      button.innerHTML = showing
        ? '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m3 3 18 18M10.6 10.6a2 2 0 0 0 2.8 2.8"/><path d="M9.9 5.2A10.8 10.8 0 0 1 12 5c6.4 0 10 7 10 7a17 17 0 0 1-3.1 3.8M6.2 6.2C3.5 8 2 12 2 12s3.6 7 10 7a10.7 10.7 0 0 0 4-.8"/></svg>'
        : '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>';
    });
  });

  const requirements = [
    ["uppercase", (password) => /\p{Lu}/u.test(password)],
    ["length", (password) => password.length >= 12],
    ["number", (password) => /\p{N}/u.test(password)],
    ["special", (password) => /[\p{P}\p{S}]/u.test(password)]
  ];

  document.querySelectorAll("[data-password-strength]").forEach((input) => {
    const meter = input.closest("form")?.querySelector("[data-password-strength-meter]");
    if (!meter) return;

    const bar = meter.querySelector("[data-strength-bar]");
    const value = meter.querySelector("[data-strength-value]");
    const progress = meter.querySelector('[role="progressbar"]');

    input.addEventListener("input", () => {
      const password = input.value;
      let score = 0;

      for (const [name, matches] of requirements) {
        const met = matches(password);
        if (met) score += 25;
        meter.querySelector(`[data-rule="${name}"]`)?.classList.toggle("is-met", met);
      }

      bar.style.width = `${score}%`;
      value.textContent = `${score}%`;
      progress.setAttribute("aria-valuenow", String(score));
    });
  });
})();
