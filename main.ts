import { App, Modal, Plugin, MarkdownView, Notice, SuggestModal, TFile } from "obsidian";

// ─── CVSS 3.1 metric definitions ────────────────────────────────────────────

const METRICS = {
  AV: {
    label: "Attack Vector",
    abbr: "AV",
    options: [
      { label: "Network",  value: "N", weight: 0.85 },
      { label: "Adjacent", value: "A", weight: 0.62 },
      { label: "Local",    value: "L", weight: 0.55 },
      { label: "Physical", value: "P", weight: 0.20 },
    ],
  },
  AC: {
    label: "Attack Complexity",
    abbr: "AC",
    options: [
      { label: "Low",  value: "L", weight: 0.77 },
      { label: "High", value: "H", weight: 0.44 },
    ],
  },
  PR: {
    label: "Privileges Required",
    abbr: "PR",
    options: [
      { label: "None", value: "N", weight: 0.85 },
      { label: "Low",  value: "L", weight: 0.62 }, // adjusted for Scope Changed below
      { label: "High", value: "H", weight: 0.27 }, // adjusted for Scope Changed below
    ],
  },
  UI: {
    label: "User Interaction",
    abbr: "UI",
    options: [
      { label: "None",     value: "N", weight: 0.85 },
      { label: "Required", value: "R", weight: 0.62 },
    ],
  },
  S: {
    label: "Scope",
    abbr: "S",
    options: [
      { label: "Unchanged", value: "U" },
      { label: "Changed",   value: "C" },
    ],
  },
  C: {
    label: "Confidentiality",
    abbr: "C",
    options: [
      { label: "None", value: "N", weight: 0.00 },
      { label: "Low",  value: "L", weight: 0.22 },
      { label: "High", value: "H", weight: 0.56 },
    ],
  },
  I: {
    label: "Integrity",
    abbr: "I",
    options: [
      { label: "None", value: "N", weight: 0.00 },
      { label: "Low",  value: "L", weight: 0.22 },
      { label: "High", value: "H", weight: 0.56 },
    ],
  },
  A: {
    label: "Availability",
    abbr: "A",
    options: [
      { label: "None", value: "N", weight: 0.00 },
      { label: "Low",  value: "L", weight: 0.22 },
      { label: "High", value: "H", weight: 0.56 },
    ],
  },
} as const;

// ─── Score calculation ───────────────────────────────────────────────────────

function roundup(value: number): number {
  const int = Math.round(value * 100000);
  if (int % 10000 === 0) return int / 100000;
  return (Math.floor(int / 10000) + 1) / 10;
}

interface Selection {
  AV: string; AC: string; PR: string; UI: string;
  S: string; C: string; I: string; A: string;
}

function computeScore(sel: Selection): { score: number; vector: string; severity: string } | null {
  // Ensure all metrics are selected
  for (const key of Object.keys(METRICS)) {
    if (!sel[key as keyof Selection]) return null;
  }

  const av  = METRICS.AV.options.find(o => o.value === sel.AV)!.weight;
  const ac  = METRICS.AC.options.find(o => o.value === sel.AC)!.weight;
  const ui  = METRICS.UI.options.find(o => o.value === sel.UI)!.weight;
  const c   = (METRICS.C.options.find(o => o.value === sel.C)! as { weight: number }).weight;
  const i   = (METRICS.I.options.find(o => o.value === sel.I)! as { weight: number }).weight;
  const a   = (METRICS.A.options.find(o => o.value === sel.A)! as { weight: number }).weight;

  // PR weight depends on Scope
  let pr: number;
  if (sel.PR === "N") pr = 0.85;
  else if (sel.PR === "L") pr = sel.S === "C" ? 0.50 : 0.62;
  else pr = sel.S === "C" ? 0.50 : 0.27; // H

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);

  let impact: number;
  if (sel.S === "U") {
    impact = 6.42 * iss;
  } else {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  }

  const exploitability = 8.22 * av * ac * pr * ui;

  let score: number;
  if (impact <= 0) {
    score = 0;
  } else if (sel.S === "U") {
    score = roundup(Math.min(impact + exploitability, 10));
  } else {
    score = roundup(Math.min(1.08 * (impact + exploitability), 10));
  }

  const vector = `CVSS:3.1/AV:${sel.AV}/AC:${sel.AC}/PR:${sel.PR}/UI:${sel.UI}/S:${sel.S}/C:${sel.C}/I:${sel.I}/A:${sel.A}`;
  const severity = score === 0 ? "None"
    : score < 4  ? "Low"
    : score < 7  ? "Medium"
    : score < 9  ? "High"
    : "Critical";

  return { score, vector, severity };
}

// ─── Findings suggest modal ──────────────────────────────────────────────────

class FindingsSuggestModal extends SuggestModal<TFile> {
  constructor(app: App) {
    super(app);
    this.setPlaceholder("Select an open finding to update CVSS…");
  }

  getSuggestions(query: string): TFile[] {
    const q = query.toLowerCase();
    return this.app.vault.getMarkdownFiles().filter(file => {
      const fm = this.app.metadataCache.getFileCache(file)?.frontmatter;
      if (!fm) return false;
      const OPEN_VALUES = ["aperto", "open", "draft"];
      const raw = fm["stato"] ?? fm["status"];
      const vals = (Array.isArray(raw) ? raw : [raw]).map((v: unknown) => String(v).toLowerCase());
      const isOpen = vals.some(v => OPEN_VALUES.includes(v));
      if (!isOpen) return false;
      return !q || file.basename.toLowerCase().includes(q);
    });
  }

  renderSuggestion(file: TFile, el: HTMLElement): void {
    el.createEl("div", { text: file.basename, cls: "suggestion-title" });
    el.createEl("small", { text: file.path, cls: "suggestion-note" });
  }

  onChooseSuggestion(file: TFile): void {
    new CvssModal(this.app, file).open();
  }
}

// ─── Modal ───────────────────────────────────────────────────────────────────

class CvssModal extends Modal {
  private selection: Partial<Selection> = {};
  private scoreEl!: HTMLElement;
  private vectorEl!: HTMLElement;
  private severityEl!: HTMLElement;
  private insertBtn!: HTMLButtonElement;
  private targetFile?: TFile;

  constructor(app: App, targetFile?: TFile) {
    super(app);
    this.targetFile = targetFile;
  }

  onOpen() {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.addClass("cvss-modal");
    this.modalEl.addClass("cvss-modal-wide");

    contentEl.createEl("h2", { text: "CVSS 3.1 Calculator" });

    // Metric groups
    const groups = [
      { title: "Exploitability", keys: ["AV", "AC", "PR", "UI"] as const },
      { title: "Scope",          keys: ["S"]                    as const },
      { title: "Impact",         keys: ["C", "I", "A"]          as const },
    ];

    for (const group of groups) {
      const section = contentEl.createDiv("cvss-section");
      section.createEl("h3", { text: group.title });
      const grid = section.createDiv("cvss-grid");

      for (const key of group.keys) {
        const metric = METRICS[key];
        const col = grid.createDiv("cvss-metric");
        col.createEl("div", { text: metric.label, cls: "cvss-metric-label" });

        const btnRow = col.createDiv("cvss-btn-row");
        for (const opt of metric.options) {
          const btn = btnRow.createEl("button", { text: opt.label, cls: "cvss-opt-btn" });
          btn.dataset.metric = key;
          btn.dataset.value  = opt.value;
          btn.addEventListener("click", () => {
            // Deselect siblings
            btnRow.querySelectorAll(".cvss-opt-btn").forEach(b => b.removeClass("cvss-selected"));
            btn.addClass("cvss-selected");
            (this.selection as Record<string, string>)[key] = opt.value;
            this.updateScore();
          });
        }
      }
    }

    // Score display
    const scoreSection = contentEl.createDiv("cvss-score-section");
    const scoreBadge   = scoreSection.createDiv("cvss-score-badge");
    this.scoreEl       = scoreBadge.createEl("span", { text: "–", cls: "cvss-score-number" });
    this.severityEl    = scoreBadge.createEl("span", { text: "", cls: "cvss-severity-label" });
    this.vectorEl      = scoreSection.createEl("div", { text: "", cls: "cvss-vector-string" });

    // Action buttons
    const actions = contentEl.createDiv("cvss-actions");

    const copyBtn = actions.createEl("button", { text: "Copy vector", cls: "cvss-action-btn" });
    copyBtn.addEventListener("click", () => {
      const vec = this.vectorEl.getText();
      if (vec) {
        void navigator.clipboard.writeText(vec);
        new Notice("Vector copied to clipboard");
      }
    });

    this.insertBtn = actions.createEl("button", {
      text: this.targetFile ? "Update CVSS" : "Insert into note",
      cls: "cvss-action-btn cvss-primary",
    });
    this.insertBtn.disabled = true;
    this.insertBtn.addEventListener("click", () => {
      if (this.targetFile) void this.updateFrontmatter();
      else this.insertIntoNote();
    });

    // Pre-populate from existing cvss_vector if editing a finding
    if (this.targetFile) {
      const fm = this.app.metadataCache.getFileCache(this.targetFile)?.frontmatter;
      const existing = fm?.["cvss_vector"] as string | undefined;
      if (existing) this.prePopulateFromVector(existing, contentEl);
    }
  }

  private updateScore() {
    const result = computeScore(this.selection as Selection);
    if (!result) {
      this.scoreEl.setText("–");
      this.severityEl.setText("");
      this.severityEl.className = "cvss-severity-label";
      this.vectorEl.setText("");
      this.insertBtn.disabled = true;
      return;
    }

    this.scoreEl.setText(result.score.toFixed(1));
    this.severityEl.setText(result.severity);
    this.severityEl.className = `cvss-severity-label cvss-sev-${result.severity.toLowerCase()}`;
    this.vectorEl.setText(result.vector);
    this.insertBtn.disabled = false;
  }

  private insertIntoNote() {
    const result = computeScore(this.selection as Selection);
    if (!result) return;

    const view = this.app.workspace.getActiveViewOfType(MarkdownView);
    if (!view) {
      new Notice("No active markdown note");
      return;
    }

    const editor = view.editor;
    const text = `**CVSS 3.1 Score:** ${result.score.toFixed(1)} (${result.severity})\n\`${result.vector}\``;
    editor.replaceSelection(text);
    this.close();
  }

  private async updateFrontmatter() {
    const result = computeScore(this.selection as Selection);
    if (!result || !this.targetFile) return;

    const severity = result.severity.toUpperCase();
    const score    = result.score.toFixed(1);
    const link     = `https://www.first.org/cvss/calculator/3.1#${result.vector}`;

    await this.app.fileManager.processFrontMatter(this.targetFile, (fm) => {
      fm["cvss_vector"]   = result.vector;
      fm["cvss_link"]     = link;
      fm["cvss_score"]    = score;
      fm["cvss_severity"] = severity;
    });

    new Notice(`CVSS updated for ${this.targetFile.basename}`);
    this.close();
  }

  private prePopulateFromVector(vector: string, contentEl: HTMLElement) {
    const parts = vector.replace("CVSS:3.1/", "").split("/");
    for (const part of parts) {
      const [key, value] = part.split(":");
      if (!key || !value) continue;
      (this.selection as Record<string, string>)[key] = value;
      const btn = contentEl.querySelector(`[data-metric="${key}"][data-value="${value}"]`) as HTMLElement | null;
      if (btn) {
        btn.parentElement?.querySelectorAll(".cvss-opt-btn").forEach(b => b.removeClass("cvss-selected"));
        btn.addClass("cvss-selected");
      }
    }
    this.updateScore();
  }

  onClose() {
    this.contentEl.empty();
  }
}


export default class CvssPlugin extends Plugin {
  onload() {
    this.addRibbonIcon("shield", "Open CVSS 3.1 Calculator", () => {
      new CvssModal(this.app).open();
    });

    this.addCommand({
      id: "cvss",
      name: "CVSS Calculator",
      callback: () => new CvssModal(this.app).open(),
    });

    this.addCommand({
      id: "cvss-update-finding",
      name: "Change CVSS of open finding",
      callback: () => new FindingsSuggestModal(this.app).open(),
    });

    this.addCommand({
      id: "cvss-update-current",
      name: "Change CVSS of current note",
      callback: () => {
        const file = this.app.workspace.getActiveFile();
        if (!file) { new Notice("No active note"); return; }
        new CvssModal(this.app, file).open();
      },
    });
  }
}
