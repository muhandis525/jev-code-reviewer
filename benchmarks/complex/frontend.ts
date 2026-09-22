type Profile = { name: string; bio: string };

export function renderProfile(node: HTMLElement, profile: Profile): void {
  node.innerHTML = `<h2>${profile.name}</h2><p>${profile.bio}</p>`;
}

export function renderSafeName(node: HTMLElement, profile: Profile): void {
  node.textContent = profile.name;
}

export function runFormula(formula: string): unknown {
  return eval(formula);
}

export function isEnabled(value: unknown): boolean {
  return value == true;
}

async function saveProfile(profile: Profile): Promise<void> {
  await fetch("/api/profile", {
    method: "POST",
    body: JSON.stringify(profile),
  });
}

export function saveAndRedirect(profile: Profile): void {
  saveProfile(profile);
  window.location.assign("/done");
}

export function parseSettings(raw: string): unknown {
  return JSON.parse(raw);
}
