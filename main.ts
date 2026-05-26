import { App, Modal, Plugin, MarkdownView, Notice, SuggestModal, TFile } from "obsidian";

// ─── CVSS 4.0 metric definitions ────────────────────────────────────────────

const METRICS = {
  AV: {
    label: "Attack Vector",
    abbr: "AV",
    options: [
      { label: "Network",  value: "N" },
      { label: "Adjacent", value: "A" },
      { label: "Local",    value: "L" },
      { label: "Physical", value: "P" },
    ],
  },
  AC: {
    label: "Attack Complexity",
    abbr: "AC",
    options: [
      { label: "Low",  value: "L" },
      { label: "High", value: "H" },
    ],
  },
  AT: {
    label: "Attack Requirements",
    abbr: "AT",
    options: [
      { label: "None",    value: "N" },
      { label: "Present", value: "P" },
    ],
  },
  PR: {
    label: "Privileges Required",
    abbr: "PR",
    options: [
      { label: "None", value: "N" },
      { label: "Low",  value: "L" },
      { label: "High", value: "H" },
    ],
  },
  UI: {
    label: "User Interaction",
    abbr: "UI",
    options: [
      { label: "None",    value: "N" },
      { label: "Passive", value: "P" },
      { label: "Active",  value: "A" },
    ],
  },
  VC: {
    label: "Confidentiality (Vulnerable System)",
    abbr: "VC",
    options: [
      { label: "High", value: "H" },
      { label: "Low",  value: "L" },
      { label: "None", value: "N" },
    ],
  },
  VI: {
    label: "Integrity (Vulnerable System)",
    abbr: "VI",
    options: [
      { label: "High", value: "H" },
      { label: "Low",  value: "L" },
      { label: "None", value: "N" },
    ],
  },
  VA: {
    label: "Availability (Vulnerable System)",
    abbr: "VA",
    options: [
      { label: "High", value: "H" },
      { label: "Low",  value: "L" },
      { label: "None", value: "N" },
    ],
  },
  SC: {
    label: "Confidentiality (Subsequent Systems)",
    abbr: "SC",
    options: [
      { label: "High", value: "H" },
      { label: "Low",  value: "L" },
      { label: "None", value: "N" },
    ],
  },
  SI: {
    label: "Integrity (Subsequent Systems)",
    abbr: "SI",
    options: [
      { label: "High", value: "H" },
      { label: "Low",  value: "L" },
      { label: "None", value: "N" },
    ],
  },
  SA: {
    label: "Availability (Subsequent Systems)",
    abbr: "SA",
    options: [
      { label: "High", value: "H" },
      { label: "Low",  value: "L" },
      { label: "None", value: "N" },
    ],
  },
} as const;

// ─── CVSS 4.0 scoring tables (source: FIRSTdotorg/cvss-v4-calculator) ────────

// Macro-vector lookup: key = EQ1+EQ2+EQ3+EQ4+EQ5+EQ6
const CVSS40_LOOKUP: Record<string, number> = {
  "000000": 10,   "000001": 9.9,  "000010": 9.8,  "000011": 9.5,
  "000020": 9.5,  "000021": 9.2,  "000100": 10,   "000101": 9.6,
  "000110": 9.3,  "000111": 8.7,  "000120": 9.1,  "000121": 8.1,
  "000200": 9.3,  "000201": 9,    "000210": 8.9,  "000211": 8,
  "000220": 8.1,  "000221": 6.8,  "001000": 9.8,  "001001": 9.5,
  "001010": 9.5,  "001011": 9.2,  "001020": 9,    "001021": 8.4,
  "001100": 9.3,  "001101": 9.2,  "001110": 8.9,  "001111": 8.1,
  "001120": 8.1,  "001121": 6.5,  "001200": 8.8,  "001201": 8,
  "001210": 7.8,  "001211": 7,    "001220": 6.9,  "001221": 4.8,
  "002001": 9.2,  "002011": 8.2,  "002021": 7.2,  "002101": 7.9,
  "002111": 6.9,  "002121": 5,    "002201": 6.9,  "002211": 5.5,
  "002221": 2.7,  "010000": 9.9,  "010001": 9.7,  "010010": 9.5,
  "010011": 9.2,  "010020": 9.2,  "010021": 8.5,  "010100": 9.5,
  "010101": 9.1,  "010110": 9,    "010111": 8.3,  "010120": 8.4,
  "010121": 7.1,  "010200": 9.2,  "010201": 8.1,  "010210": 8.2,
  "010211": 7.1,  "010220": 7.2,  "010221": 5.3,  "011000": 9.5,
  "011001": 9.3,  "011010": 9.2,  "011011": 8.5,  "011020": 8.5,
  "011021": 7.3,  "011100": 9.2,  "011101": 8.2,  "011110": 8,
  "011111": 7.2,  "011120": 7,    "011121": 5.9,  "011200": 8.4,
  "011201": 7,    "011210": 7.1,  "011211": 5.2,  "011220": 5,
  "011221": 3,    "012001": 8.6,  "012011": 7.5,  "012021": 5.2,
  "012101": 7.1,  "012111": 5.2,  "012121": 2.9,  "012201": 6.3,
  "012211": 2.9,  "012221": 1.7,  "100000": 9.8,  "100001": 9.5,
  "100010": 9.4,  "100011": 8.7,  "100020": 9.1,  "100021": 8.1,
  "100100": 9.4,  "100101": 8.9,  "100110": 8.6,  "100111": 7.4,
  "100120": 7.7,  "100121": 6.4,  "100200": 8.7,  "100201": 7.5,
  "100210": 7.4,  "100211": 6.3,  "100220": 6.3,  "100221": 4.9,
  "101000": 9.4,  "101001": 8.9,  "101010": 8.8,  "101011": 7.7,
  "101020": 7.6,  "101021": 6.7,  "101100": 8.6,  "101101": 7.6,
  "101110": 7.4,  "101111": 5.8,  "101120": 5.9,  "101121": 5,
  "101200": 7.2,  "101201": 5.7,  "101210": 5.7,  "101211": 5.2,
  "101220": 5.2,  "101221": 2.5,  "102001": 8.3,  "102011": 7,
  "102021": 5.4,  "102101": 6.5,  "102111": 5.8,  "102121": 2.6,
  "102201": 5.3,  "102211": 2.1,  "102221": 1.3,  "110000": 9.5,
  "110001": 9,    "110010": 8.8,  "110011": 7.6,  "110020": 7.6,
  "110021": 7,    "110100": 9,    "110101": 7.7,  "110110": 7.5,
  "110111": 6.2,  "110120": 6.1,  "110121": 5.3,  "110200": 7.7,
  "110201": 6.6,  "110210": 6.8,  "110211": 5.9,  "110220": 5.2,
  "110221": 3,    "111000": 8.9,  "111001": 7.8,  "111010": 7.6,
  "111011": 6.7,  "111020": 6.2,  "111021": 5.8,  "111100": 7.4,
  "111101": 5.9,  "111110": 5.7,  "111111": 5.7,  "111120": 4.7,
  "111121": 2.3,  "111200": 6.1,  "111201": 5.2,  "111210": 5.7,
  "111211": 2.9,  "111220": 2.4,  "111221": 1.6,  "112001": 7.1,
  "112011": 5.9,  "112021": 3,    "112101": 5.8,  "112111": 2.6,
  "112121": 1.5,  "112201": 2.3,  "112211": 1.3,  "112221": 0.6,
  "200000": 9.3,  "200001": 8.7,  "200010": 8.6,  "200011": 7.2,
  "200020": 7.5,  "200021": 5.8,  "200100": 8.6,  "200101": 7.4,
  "200110": 7.4,  "200111": 6.1,  "200120": 5.6,  "200121": 3.4,
  "200200": 7,    "200201": 5.4,  "200210": 5.2,  "200211": 4,
  "200220": 4,    "200221": 2.2,  "201000": 8.5,  "201001": 7.5,
  "201010": 7.4,  "201011": 5.5,  "201020": 6.2,  "201021": 5.1,
  "201100": 7.2,  "201101": 5.7,  "201110": 5.5,  "201111": 4.1,
  "201120": 4.6,  "201121": 1.9,  "201200": 5.3,  "201201": 3.6,
  "201210": 3.4,  "201211": 1.9,  "201220": 1.9,  "201221": 0.8,
  "202001": 6.4,  "202011": 5.1,  "202021": 2,    "202101": 4.7,
  "202111": 2.1,  "202121": 1.1,  "202201": 2.4,  "202211": 0.9,
  "202221": 0.4,  "210000": 8.8,  "210001": 7.5,  "210010": 7.3,
  "210011": 5.3,  "210020": 6,    "210021": 5,    "210100": 7.3,
  "210101": 5.5,  "210110": 5.9,  "210111": 4,    "210120": 4.1,
  "210121": 2,    "210200": 5.4,  "210201": 4.3,  "210210": 4.5,
  "210211": 2.2,  "210220": 2,    "210221": 1.1,  "211000": 7.5,
  "211001": 5.5,  "211010": 5.8,  "211011": 4.5,  "211020": 4,
  "211021": 2.1,  "211100": 6.1,  "211101": 5.1,  "211110": 4.8,
  "211111": 1.8,  "211120": 2,    "211121": 0.9,  "211200": 4.6,
  "211201": 1.8,  "211210": 1.7,  "211211": 0.7,  "211220": 0.8,
  "211221": 0.2,  "212001": 5.3,  "212011": 2.4,  "212021": 1.4,
  "212101": 2.4,  "212111": 1.2,  "212121": 0.5,  "212201": 1,
  "212211": 0.3,  "212221": 0.1,
};

// Max compositions for each EQ group (highest-severity vectors within each level)
const MAX_COMPOSED: {
  eq1: Record<number, string[]>;
  eq2: Record<number, string[]>;
  eq3: Record<number, Record<string, string[]>>;
  eq4: Record<number, string[]>;
  eq5: Record<number, string[]>;
} = {
  eq1: {
    0: ["AV:N/PR:N/UI:N/"],
    1: ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
    2: ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
  },
  eq2: {
    0: ["AC:L/AT:N/"],
    1: ["AC:H/AT:N/", "AC:L/AT:P/"],
  },
  eq3: {
    0: {
      "0": ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
      "1": ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"],
    },
    1: {
      "0": ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
      "1": [
        "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
        "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
        "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
      ],
    },
    2: {
      "1": ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"],
    },
  },
  eq4: {
    0: ["SC:H/SI:S/SA:S/"],
    1: ["SC:H/SI:H/SA:H/"],
    2: ["SC:L/SI:L/SA:L/"],
  },
  eq5: {
    0: ["E:A/"],
    1: ["E:P/"],
    2: ["E:U/"],
  },
};

// Max severity distances within each EQ level (+1 per step = 0.1)
const MAX_SEVERITY: {
  eq1: Record<number, number>;
  eq2: Record<number, number>;
  eq3eq6: Record<number, Record<number, number>>;
  eq4: Record<number, number>;
  eq5: Record<number, number>;
} = {
  eq1:   { 0: 1, 1: 4, 2: 5 },
  eq2:   { 0: 1, 1: 2 },
  eq3eq6: {
    0: { 0: 7, 1: 6 },
    1: { 0: 8, 1: 8 },
    2: { 1: 10 },
  },
  eq4: { 0: 6, 1: 5, 2: 4 },
  eq5: { 0: 1, 1: 1, 2: 1 },
};

// ─── Scoring helpers ─────────────────────────────────────────────────────────

interface Selection {
  AV: string; AC: string; AT: string; PR: string; UI: string;
  VC: string; VI: string; VA: string;
  SC: string; SI: string; SA: string;
}

// Resolve effective metric value, applying CVSS 4.0 X-defaults
function m(sel: Record<string, string>, metric: string): string {
  const val = sel[metric] ?? "X";
  if (metric === "E"  && val === "X") return "A";
  if (metric === "CR" && val === "X") return "H";
  if (metric === "IR" && val === "X") return "H";
  if (metric === "AR" && val === "X") return "H";
  // Environmental override (M-prefix)
  const modKey = "M" + metric;
  if (sel[modKey] && sel[modKey] !== "X") return sel[modKey];
  return val;
}

function extractValueMetric(metric: string, str: string): string {
  const idx = str.indexOf(metric + ":");
  if (idx < 0) return "";
  const rest = str.slice(idx + metric.length + 1);
  const slash = rest.indexOf("/");
  return slash >= 0 ? rest.substring(0, slash) : rest;
}

function macroVector(full: Record<string, string>): string {
  let eq1: string;
  if (m(full, "AV") === "N" && m(full, "PR") === "N" && m(full, "UI") === "N") {
    eq1 = "0";
  } else if (
    (m(full, "AV") === "N" || m(full, "PR") === "N" || m(full, "UI") === "N") &&
    !(m(full, "AV") === "N" && m(full, "PR") === "N" && m(full, "UI") === "N") &&
    m(full, "AV") !== "P"
  ) {
    eq1 = "1";
  } else {
    eq1 = "2";
  }

  const eq2 = (m(full, "AC") === "L" && m(full, "AT") === "N") ? "0" : "1";

  let eq3: number;
  if (m(full, "VC") === "H" && m(full, "VI") === "H") {
    eq3 = 0;
  } else if (m(full, "VC") === "H" || m(full, "VI") === "H" || m(full, "VA") === "H") {
    eq3 = 1;
  } else {
    eq3 = 2;
  }

  let eq4: number;
  if (m(full, "MSI") === "S" || m(full, "MSA") === "S") {
    eq4 = 0;
  } else if (m(full, "SC") === "H" || m(full, "SI") === "H" || m(full, "SA") === "H") {
    eq4 = 1;
  } else {
    eq4 = 2;
  }

  let eq5: number;
  if (m(full, "E") === "A") eq5 = 0;
  else if (m(full, "E") === "P") eq5 = 1;
  else eq5 = 2;

  let eq6: number;
  if (
    (m(full, "CR") === "H" && m(full, "VC") === "H") ||
    (m(full, "IR") === "H" && m(full, "VI") === "H") ||
    (m(full, "AR") === "H" && m(full, "VA") === "H")
  ) {
    eq6 = 0;
  } else {
    eq6 = 1;
  }

  return `${eq1}${eq2}${eq3}${eq4}${eq5}${eq6}`;
}

function buildVector(sel: Selection): string {
  return `CVSS:4.0/AV:${sel.AV}/AC:${sel.AC}/AT:${sel.AT}/PR:${sel.PR}/UI:${sel.UI}` +
    `/VC:${sel.VC}/VI:${sel.VI}/VA:${sel.VA}/SC:${sel.SC}/SI:${sel.SI}/SA:${sel.SA}`;
}

// ─── Score calculation ────────────────────────────────────────────────────────

function computeScore(sel: Selection): { score: number; vector: string; severity: string } | null {
  for (const key of Object.keys(METRICS)) {
    if (!sel[key as keyof Selection]) return null;
  }

  // Full selection object with defaults for non-base metrics
  const full: Record<string, string> = {
    ...sel,
    E: "X", CR: "X", IR: "X", AR: "X",
    MSI: "X", MSA: "X",
  };

  // Zero-impact shortcut
  const impactKeys = ["VC", "VI", "VA", "SC", "SI", "SA"] as const;
  if (impactKeys.every(k => m(full, k) === "N")) {
    return { score: 0.0, vector: buildVector(sel), severity: "None" };
  }

  // Metric severity level mappings (0.0 = best, higher = worse)
  const AV_L: Record<string, number> = { N: 0.0, A: 0.1, L: 0.2, P: 0.3 };
  const PR_L: Record<string, number> = { N: 0.0, L: 0.1, H: 0.2 };
  const UI_L: Record<string, number> = { N: 0.0, P: 0.1, A: 0.2 };
  const AC_L: Record<string, number> = { L: 0.0, H: 0.1 };
  const AT_L: Record<string, number> = { N: 0.0, P: 0.1 };
  const VC_L: Record<string, number> = { H: 0.0, L: 0.1, N: 0.2 };
  const VI_L: Record<string, number> = { H: 0.0, L: 0.1, N: 0.2 };
  const VA_L: Record<string, number> = { H: 0.0, L: 0.1, N: 0.2 };
  const SC_L: Record<string, number> = { H: 0.1, L: 0.2, N: 0.3 };
  const SI_L: Record<string, number> = { S: 0.0, H: 0.1, L: 0.2, N: 0.3 };
  const SA_L: Record<string, number> = { S: 0.0, H: 0.1, L: 0.2, N: 0.3 };
  const CR_L: Record<string, number> = { H: 0.0, M: 0.1, L: 0.2 };
  const IR_L: Record<string, number> = { H: 0.0, M: 0.1, L: 0.2 };
  const AR_L: Record<string, number> = { H: 0.0, M: 0.1, L: 0.2 };

  const mv = macroVector(full);
  const eq1 = parseInt(mv[0]);
  const eq2 = parseInt(mv[1]);
  const eq3 = parseInt(mv[2]);
  const eq4 = parseInt(mv[3]);
  const eq5 = parseInt(mv[4]);
  const eq6 = parseInt(mv[5]);

  let value = CVSS40_LOOKUP[mv];
  if (value === undefined) return null;

  // Next lower macro vectors for each EQ group
  const nlo_eq1 = `${eq1+1}${eq2}${eq3}${eq4}${eq5}${eq6}`;
  const nlo_eq2 = `${eq1}${eq2+1}${eq3}${eq4}${eq5}${eq6}`;

  let nlo_eq3eq6: string;
  let nlo_eq3eq6_l: string | undefined;
  let nlo_eq3eq6_r: string | undefined;

  if      (eq3 === 1 && eq6 === 1) nlo_eq3eq6 = `${eq1}${eq2}${eq3+1}${eq4}${eq5}${eq6}`;
  else if (eq3 === 0 && eq6 === 1) nlo_eq3eq6 = `${eq1}${eq2}${eq3+1}${eq4}${eq5}${eq6}`;
  else if (eq3 === 1 && eq6 === 0) nlo_eq3eq6 = `${eq1}${eq2}${eq3}${eq4}${eq5}${eq6+1}`;
  else if (eq3 === 0 && eq6 === 0) {
    nlo_eq3eq6_l = `${eq1}${eq2}${eq3}${eq4}${eq5}${eq6+1}`;
    nlo_eq3eq6_r = `${eq1}${eq2}${eq3+1}${eq4}${eq5}${eq6}`;
    nlo_eq3eq6 = nlo_eq3eq6_l;
  } else {
    nlo_eq3eq6 = `${eq1}${eq2}${eq3+1}${eq4}${eq5}${eq6+1}`;
  }

  const nlo_eq4 = `${eq1}${eq2}${eq3}${eq4+1}${eq5}${eq6}`;
  const nlo_eq5 = `${eq1}${eq2}${eq3}${eq4}${eq5+1}${eq6}`;

  const s_eq1 = CVSS40_LOOKUP[nlo_eq1] ?? NaN;
  const s_eq2 = CVSS40_LOOKUP[nlo_eq2] ?? NaN;
  let s_eq3eq6: number;
  if (eq3 === 0 && eq6 === 0) {
    const l = CVSS40_LOOKUP[nlo_eq3eq6_l!] ?? NaN;
    const r = CVSS40_LOOKUP[nlo_eq3eq6_r!] ?? NaN;
    s_eq3eq6 = (!isNaN(l) && !isNaN(r)) ? Math.max(l, r) : (!isNaN(l) ? l : r);
  } else {
    s_eq3eq6 = CVSS40_LOOKUP[nlo_eq3eq6] ?? NaN;
  }
  const s_eq4 = CVSS40_LOOKUP[nlo_eq4] ?? NaN;
  const s_eq5 = CVSS40_LOOKUP[nlo_eq5] ?? NaN;

  // Build all max-vector combinations and find one >= our severity
  const eq1_maxes  = MAX_COMPOSED.eq1[eq1];
  const eq2_maxes  = MAX_COMPOSED.eq2[eq2];
  const eq3_maxes  = MAX_COMPOSED.eq3[eq3][String(eq6)];
  const eq4_maxes  = MAX_COMPOSED.eq4[eq4];
  const eq5_maxes  = MAX_COMPOSED.eq5[eq5];

  let sd_AV = 0, sd_PR = 0, sd_UI = 0;
  let sd_AC = 0, sd_AT = 0;
  let sd_VC = 0, sd_VI = 0, sd_VA = 0;
  let sd_SC = 0, sd_SI = 0, sd_SA = 0;
  let sd_CR = 0, sd_IR = 0, sd_AR = 0;

  outer:
  for (const e1 of eq1_maxes) {
    for (const e2 of eq2_maxes) {
      for (const e3 of (eq3_maxes ?? [])) {
        for (const e4 of eq4_maxes) {
          for (const e5 of eq5_maxes) {
            const mv_str = e1 + e2 + e3 + e4 + e5;
            sd_AV = AV_L[m(full,"AV")] - AV_L[extractValueMetric("AV", mv_str)];
            sd_PR = PR_L[m(full,"PR")] - PR_L[extractValueMetric("PR", mv_str)];
            sd_UI = UI_L[m(full,"UI")] - UI_L[extractValueMetric("UI", mv_str)];
            sd_AC = AC_L[m(full,"AC")] - AC_L[extractValueMetric("AC", mv_str)];
            sd_AT = AT_L[m(full,"AT")] - AT_L[extractValueMetric("AT", mv_str)];
            sd_VC = VC_L[m(full,"VC")] - VC_L[extractValueMetric("VC", mv_str)];
            sd_VI = VI_L[m(full,"VI")] - VI_L[extractValueMetric("VI", mv_str)];
            sd_VA = VA_L[m(full,"VA")] - VA_L[extractValueMetric("VA", mv_str)];
            sd_SC = SC_L[m(full,"SC")] - SC_L[extractValueMetric("SC", mv_str)];
            sd_SI = SI_L[m(full,"SI")] - SI_L[extractValueMetric("SI", mv_str)];
            sd_SA = SA_L[m(full,"SA")] - SA_L[extractValueMetric("SA", mv_str)];
            sd_CR = CR_L[m(full,"CR")] - CR_L[extractValueMetric("CR", mv_str)];
            sd_IR = IR_L[m(full,"IR")] - IR_L[extractValueMetric("IR", mv_str)];
            sd_AR = AR_L[m(full,"AR")] - AR_L[extractValueMetric("AR", mv_str)];

            if ([sd_AV,sd_PR,sd_UI,sd_AC,sd_AT,sd_VC,sd_VI,sd_VA,
                 sd_SC,sd_SI,sd_SA,sd_CR,sd_IR,sd_AR].some(d => d < 0)) continue;
            break outer;
          }
        }
      }
    }
  }

  const step = 0.1;
  const dist_eq1    = sd_AV + sd_PR + sd_UI;
  const dist_eq2    = sd_AC + sd_AT;
  const dist_eq3eq6 = sd_VC + sd_VI + sd_VA + sd_CR + sd_IR + sd_AR;
  const dist_eq4    = sd_SC + sd_SI + sd_SA;

  const avail1    = value - s_eq1;
  const avail2    = value - s_eq2;
  const avail3eq6 = value - s_eq3eq6;
  const avail4    = value - s_eq4;
  const avail5    = value - s_eq5;

  const max1    = MAX_SEVERITY.eq1[eq1]           * step;
  const max2    = MAX_SEVERITY.eq2[eq2]           * step;
  const max3eq6 = MAX_SEVERITY.eq3eq6[eq3][eq6]  * step;
  const max4    = MAX_SEVERITY.eq4[eq4]           * step;

  let n = 0;
  let norm1 = 0, norm2 = 0, norm3 = 0, norm4 = 0, norm5 = 0;

  if (!isNaN(avail1))    { n++; norm1 = avail1    * (dist_eq1    / max1);    }
  if (!isNaN(avail2))    { n++; norm2 = avail2    * (dist_eq2    / max2);    }
  if (!isNaN(avail3eq6)) { n++; norm3 = avail3eq6 * (dist_eq3eq6 / max3eq6); }
  if (!isNaN(avail4))    { n++; norm4 = avail4    * (dist_eq4    / max4);    }
  if (!isNaN(avail5))    { n++; /* norm5 = 0 for base (E=X) */ }

  const mean_dist = n === 0 ? 0 : (norm1 + norm2 + norm3 + norm4 + norm5) / n;
  value = Math.max(0, Math.min(10, value - mean_dist));
  const score = Math.round(value * 10) / 10;

  const severity = score === 0   ? "None"
    : score < 4  ? "Low"
    : score < 7  ? "Medium"
    : score < 9  ? "High"
    : "Critical";

  return { score, vector: buildVector(sel), severity };
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

    contentEl.createEl("h2", { text: "CVSS 4.0 Calculator" });

    const groups = [
      { title: "Exploitability",             keys: ["AV", "AC", "AT", "PR", "UI"] as const },
      { title: "Vulnerable System Impact",   keys: ["VC", "VI", "VA"]             as const },
      { title: "Subsequent Systems Impact",  keys: ["SC", "SI", "SA"]             as const },
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
            btnRow.querySelectorAll(".cvss-opt-btn").forEach(b => b.removeClass("cvss-selected"));
            btn.addClass("cvss-selected");
            (this.selection as Record<string, string>)[key] = opt.value;
            this.updateScore();
          });
        }
      }
    }

    const scoreSection = contentEl.createDiv("cvss-score-section");
    const scoreBadge   = scoreSection.createDiv("cvss-score-badge");
    this.scoreEl       = scoreBadge.createEl("span", { text: "–", cls: "cvss-score-number" });
    this.severityEl    = scoreBadge.createEl("span", { text: "", cls: "cvss-severity-label" });
    this.vectorEl      = scoreSection.createEl("div", { text: "", cls: "cvss-vector-string" });

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
    const text = `**CVSS 4.0 Score:** ${result.score.toFixed(1)} (${result.severity})\n\`${result.vector}\``;
    editor.replaceSelection(text);
    this.close();
  }

  private async updateFrontmatter() {
    const result = computeScore(this.selection as Selection);
    if (!result || !this.targetFile) return;

    const severity = result.severity.toUpperCase();
    const score    = result.score.toFixed(1);
    const link     = `https://www.first.org/cvss/calculator/4.0#${result.vector}`;

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
    const parts = vector.replace(/^CVSS:4\.0\//, "").split("/");
    for (const part of parts) {
      const [key, value] = part.split(":");
      if (!key || !value || !(key in METRICS)) continue;
      (this.selection as Record<string, string>)[key] = value;
      const btn = contentEl.querySelector(
        `[data-metric="${key}"][data-value="${value}"]`
      ) as HTMLElement | null;
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
    this.addRibbonIcon("shield", "Open CVSS 4.0 Calculator", () => {
      new CvssModal(this.app).open();
    });

    this.addCommand({
      id: "cvss",
      name: "CVSS 4.0 Calculator",
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
