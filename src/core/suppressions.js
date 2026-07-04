function globToRegex(pattern) {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "<<GLOBSTAR>>")
    .replace(/\*/g, "[^/]*")
    .replace(/<<GLOBSTAR>>/g, ".*");
  return new RegExp("^" + escaped + "$");
}

function isExpired(expires) {
  if (!expires) return false;
  try {
    return new Date(expires) < new Date();
  } catch {
    return false;
  }
}

export function shouldSuppress(finding, suppressions) {
  for (const rule of suppressions) {
    if (isExpired(rule.expires)) continue;

    const ruleMatch = rule.rule_id === "*" || rule.rule_id === finding.source?.ruleId;
    if (!ruleMatch) continue;

    const pathMatch = rule.path === "*" || finding.files?.some((f) => {
      const re = globToRegex(rule.path);
      return re.test(f);
    });
    if (!pathMatch) continue;

    return { suppressed: true, reason: rule.reason || "Suppressed by config" };
  }

  return { suppressed: false };
}

export function applySuppressions(findings, suppressions) {
  const visible = [];
  const suppressed = [];

  for (const finding of findings) {
    const result = shouldSuppress(finding, suppressions);
    if (result.suppressed) {
      suppressed.push({ ...finding, suppression_reason: result.reason });
    } else {
      visible.push(finding);
    }
  }

  return { visible, suppressed };
}
