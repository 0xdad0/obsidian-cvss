# CVSS 3.1 Calculator — Obsidian Plugin

An Obsidian plugin that opens a single popup to compute [CVSS 3.1](https://www.first.org/cvss/v3.1/specification-document) scores interactively. Select all metric options, see the score update in real time, then copy the vector string or insert the result directly into your note.

---

## Features

- Single wide modal — all 8 Base Score metrics visible without scrolling
- Live score computation as you click options
- Color-coded severity badge (None / Low / Medium / High / Critical)
- Displays the full CVSS vector string (e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **Copy Vector** — copies the vector string to the clipboard
- **Insert into note** — inserts the score and vector at the cursor in the active markdown note
- **Change CVSS of open finding** — fuzzy-search all open findings and update their CVSS frontmatter properties in one step
- **Change CVSS of current note** — update the CVSS of whatever note is currently open, regardless of its status
- Accessible via ribbon icon (shield) or Command Palette

---

## Metrics covered

| Group | Metric | Values |
|---|---|---|
| Exploitability | Attack Vector (AV) | Network, Adjacent, Local, Physical |
| Exploitability | Attack Complexity (AC) | Low, High |
| Exploitability | Privileges Required (PR) | None, Low, High |
| Exploitability | User Interaction (UI) | None, Required |
| Scope | Scope (S) | Unchanged, Changed |
| Impact | Confidentiality (C) | None, Low, High |
| Impact | Integrity (I) | None, Low, High |
| Impact | Availability (A) | None, Low, High |

> Privileges Required weights are automatically adjusted when Scope = Changed, as per the CVSS 3.1 specification.

---

## Severity ratings

| Score range | Rating |
|---|---|
| 0.0 | None |
| 0.1 – 3.9 | Low |
| 4.0 – 6.9 | Medium |
| 7.0 – 8.9 | High |
| 9.0 – 10.0 | Critical |

---

## Installation (manual)

1. Build the plugin (see below) or download a release.
2. Copy these three files into your vault's plugin folder:
   ```
   <vault>/.obsidian/plugins/cvss-calculator/main.js
   <vault>/.obsidian/plugins/cvss-calculator/manifest.json
   <vault>/.obsidian/plugins/cvss-calculator/styles.css
   ```
3. In Obsidian, go to **Settings → Community plugins**, disable Safe Mode if prompted, and enable **CVSS 3.1 Calculator**.

---

## Development & build

### Prerequisites

- [Node.js](https://nodejs.org/) 16 or later
- npm

### Setup

```bash
git clone <repo-url>
cd obsidian-cvss
npm install
```

### Build for production

```bash
npm run build
```

Outputs `main.js` (minified, no source map) alongside `manifest.json` and `styles.css`. Copy all three to your plugin folder.

### Watch mode (development)

```bash
npm run dev
```

Watches `main.ts` for changes and rebuilds with inline source maps. Useful when the plugin folder is symlinked to the repo root:

```bash
# Example: symlink the repo directly into the vault
ln -s /path/to/obsidian-cvss /path/to/vault/.obsidian/plugins/cvss-calculator
```

Then enable the plugin in Obsidian and use **Ctrl+R** (or the "Reload app without saving" command) to pick up changes.

### Project structure

```
obsidian-cvss/
├── main.ts            # Plugin source (TypeScript)
├── main.js            # Compiled output (generated — do not edit)
├── styles.css         # Modal styles
├── manifest.json      # Obsidian plugin metadata
├── package.json       # npm scripts and dev dependencies
├── tsconfig.json      # TypeScript compiler config
└── esbuild.config.mjs # Bundler config
```

### Toolchain

| Tool | Purpose |
|---|---|
| TypeScript 4.7 | Type-safe source |
| esbuild 0.17 | Fast bundler / minifier |
| obsidian (npm) | Obsidian API type definitions |

---

## Scoring algorithm

Implements the CVSS 3.1 Base Score formula exactly as defined by FIRST:

```
ISS        = 1 − [(1 − C) × (1 − I) × (1 − A)]
Impact     = 6.42 × ISS                                         (Scope Unchanged)
           = 7.52 × [ISS − 0.029] − 3.25 × [ISS − 0.02]^15    (Scope Changed)
Exploitability = 8.22 × AV × AC × PR × UI
Base Score = Roundup(Min[Impact + Exploitability, 10])           (Scope Unchanged)
           = Roundup(Min[1.08 × (Impact + Exploitability), 10]) (Scope Changed)
```

`Roundup` returns the smallest value with one decimal place greater than or equal to the input.

---

## Usage

### Standalone calculator

1. Click the **shield icon** in the left ribbon, or open the Command Palette and run **CVSS Calculator**.
2. Click one button per metric — the score updates instantly after all 8 are selected.
3. Use **Copy Vector** to copy the vector string, or **Insert into note** to write the result at the cursor:

```
**CVSS 3.1 Score:** 9.8 (Critical)
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
```

### Update CVSS of an open finding

1. Open the Command Palette and run **Change CVSS of open finding**.
2. Type to filter — the list shows all notes whose frontmatter has `stato` or `status` set to `aperto` or `open` (case-insensitive).
3. Select a note. The CVSS calculator opens; if the note already has a `cvss_vector`, the metrics are pre-selected.
4. Adjust the metrics and click **Update CVSS**. The following frontmatter properties are written (or overwritten):

| Property | Example value |
|---|---|
| `cvss_vector` | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| `cvss_score` | `9.8` |
| `cvss_severity` | `CRITICAL` |
| `cvss_link` | `https://www.first.org/cvss/calculator/3.1#CVSS:3.1/…` |

> `cvss_severity` is always written in uppercase (`NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).

### Update CVSS of the current note

1. Open the Command Palette and run **Change CVSS of current note**.
2. The CVSS calculator opens targeting the active note — no status filter applied.
3. Metrics are pre-selected if `cvss_vector` already exists. Click **Update CVSS** to write the same four frontmatter properties listed above.

---

## License

MIT
