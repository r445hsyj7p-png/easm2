export const T = {
  bg0:    "#050810",
  bg1:    "#080c18",
  bg2:    "#0d1221",
  bg3:    "#121929",
  bg4:    "#172131",
  bg5:    "#1d2a3d",

  border:      "#1e2d45",
  border2:     "#253554",
  borderFocus: "#22c55e",

  accent:   "#22c55e",
  accent2:  "#16a34a",
  accent3:  "#0f3d20",
  accentFg: "#dcfce7",

  critical:       "#f43f5e",
  criticalBg:     "#1c0810",
  criticalBorder: "#7f1d1d",
  high:           "#f97316",
  highBg:         "#1c0e00",
  highBorder:     "#7c2d12",
  medium:         "#eab308",
  mediumBg:       "#1a1400",
  mediumBorder:   "#713f12",
  low:            "#60a5fa",
  lowBg:          "#00111e",
  lowBorder:      "#1e3a5f",
  info:           "#94a3b8",
  infoBg:         "#0d1221",
  infoBorder:     "#1e2d45",

  toolSubfinder:    "#22c55e",
  toolNaabu:        "#eab308",
  toolTheharvester: "#60a5fa",
  toolHttpx:        "#a78bfa",
  toolNuclei:       "#f43f5e",
  toolRamparts:     "#f97316",

  text0:  "#f1f5f9",
  text1:  "#94a3b8",
  text2:  "#475569",
  text3:  "#273548",

  font:     "'JetBrains Mono', 'Fira Code', monospace",
  fontSans: "'IBM Plex Sans', system-ui, sans-serif",

  cyan:   "#22c55e",
  green:  "#22c55e",
  red:    "#f43f5e",
  orange: "#f97316",
  yellow: "#eab308",
  blue:   "#60a5fa",
};

export const SEV = {
  CRITICAL: { color: T.critical, bg: T.criticalBg, border: T.criticalBorder },
  HIGH:     { color: T.high,     bg: T.highBg,     border: T.highBorder     },
  MEDIUM:   { color: T.medium,   bg: T.mediumBg,   border: T.mediumBorder   },
  LOW:      { color: T.low,      bg: T.lowBg,      border: T.lowBorder      },
  INFO:     { color: T.info,     bg: T.infoBg,     border: T.infoBorder     },
};

export const TOOL_COLOR = {
  subfinder:    T.toolSubfinder,
  naabu:        T.toolNaabu,
  theharvester: T.toolTheharvester,
  httpx:        T.toolHttpx,
  nuclei:       T.toolNuclei,
  ramparts:     T.toolRamparts,
};
