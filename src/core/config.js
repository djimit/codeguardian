import fs from "node:fs";
import path from "node:path";

const DEFAULTS = {
  fail_on: "critical",
  scanners: { secrets: true, dependencies: true, pii: true, history: false },
  suppressions: [],
  history: { enabled: true, retention_days: 90 }
};

function parseMinimalYaml(content) {
  const result = {};
  const lines = content.split("\n");
  let currentKey = null;
  let currentList = null;

  for (const rawLine of lines) {
    const line = rawLine.trimEnd();
    if (!line.trim() || line.trim().startsWith("#")) continue;

    const indent = line.length - line.trimStart().length;

    if (indent === 0 && line.includes(":")) {
      const [key, ...rest] = line.split(":");
      const value = rest.join(":").trim();
      if (value) {
        result[key.trim()] = parseScalar(value);
        currentKey = null;
        currentList = null;
      } else {
        currentKey = key.trim();
        result[currentKey] = {};
        currentList = null;
      }
    } else if (indent === 2 && line.trim().startsWith("- ")) {
      if (!currentList) {
        currentList = [];
        if (currentKey) result[currentKey] = currentList;
      }
      const item = line.trim().slice(2).trim();
      if (item.includes(":")) {
        const obj = {};
        for (const pair of item.split(",")) {
          const [k, ...v] = pair.split(":");
          obj[k.trim()] = parseScalar(v.join(":").trim());
        }
        currentList.push(obj);
      } else {
        currentList.push(parseScalar(item));
      }
    } else if (indent >= 4 && line.includes(":") && currentList) {
      const [key, ...rest] = line.trim().split(":");
      const value = rest.join(":").trim();
      if (currentList.length > 0 && typeof currentList[currentList.length - 1] === "object") {
        currentList[currentList.length - 1][key.trim()] = parseScalar(value);
      }
    } else if (indent === 2 && line.includes(":")) {
      const [key, ...rest] = line.trim().split(":");
      const value = rest.join(":").trim();
      if (currentKey && result[currentKey] && !Array.isArray(result[currentKey])) {
        result[currentKey][key.trim()] = parseScalar(value);
      }
      currentList = null;
    }
  }

  return result;
}

function parseScalar(value) {
  const unquoted = value.replace(/^["']|["']$/g, "");
  if (unquoted === "true") return true;
  if (unquoted === "false") return false;
  if (unquoted === "null") return null;
  if (/^\d+$/.test(unquoted)) return parseInt(unquoted, 10);
  if (/^\d+\.\d+$/.test(unquoted)) return parseFloat(unquoted);
  return unquoted;
}

export function loadConfig(repoRoot = ".") {
  const configPath = path.join(repoRoot, ".codeguardian.yml");
  let userConfig = {};

  try {
    const content = fs.readFileSync(configPath, "utf8");
    userConfig = parseMinimalYaml(content);
  } catch {
    // no config file, use defaults
  }

  return {
    ...DEFAULTS,
    ...userConfig,
    scanners: { ...DEFAULTS.scanners, ...(userConfig.scanners || {}) },
    suppressions: userConfig.suppressions || [],
    history: { ...DEFAULTS.history, ...(userConfig.history || {}) }
  };
}
