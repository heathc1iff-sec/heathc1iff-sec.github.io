import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const REPO_ROOT = process.cwd();
const BLOG_DIR = path.join(REPO_ROOT, "src", "content", "blog");
const FRONTMATTER_PATTERN = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/;

const TAG_DEFINITIONS = [
  {
    tag: "Enumeration",
    source: "body",
    minScore: 2,
    patterns: [
      { regex: /信息收集/i, weight: 2 },
      { regex: /端口扫描/i, weight: 2 },
      { regex: /\bnmap\b/i, weight: 2 },
      { regex: /\brustscan\b/i, weight: 2 },
      { regex: /\bgobuster\b/i, weight: 2 },
      { regex: /\bffuf\b/i, weight: 2 },
      { regex: /\bferoxbuster\b/i, weight: 2 },
      { regex: /\bdirsearch\b/i, weight: 2 },
      { regex: /\bwhatweb\b/i, weight: 1 },
      { regex: /\bnikto\b/i, weight: 1 },
      { regex: /\benum4linux\b/i, weight: 2 },
      { regex: /\barp-scan\b/i, weight: 1 },
      { regex: /\bldapsearch\b/i, weight: 2 },
      { regex: /\bsnmpwalk\b/i, weight: 2 },
      { regex: /\bshowmount\b/i, weight: 2 },
    ],
  },
  {
    tag: "Privilege Escalation",
    source: "body",
    minScore: 2,
    patterns: [
      { regex: /privilege escalation/i, weight: 2 },
      { regex: /\bprivesc\b/i, weight: 2 },
      { regex: /提权/i, weight: 2 },
      { regex: /sudo -l/i, weight: 2 },
      { regex: /\bsuid\b/i, weight: 1 },
      { regex: /\bgetcap\b/i, weight: 1 },
      { regex: /seimpersonate/i, weight: 2 },
      { regex: /juicy ?potato/i, weight: 2 },
      { regex: /rogue ?potato/i, weight: 2 },
      { regex: /printspoofer/i, weight: 2 },
      { regex: /\buac\b/i, weight: 1 },
      { regex: /\brunas\b/i, weight: 1 },
      { regex: /cron/i, weight: 1 },
      { regex: /service misconfiguration/i, weight: 1 },
    ],
  },
  {
    tag: "Active Directory",
    source: "combined",
    minScore: 4,
    patterns: [
      { regex: /active directory/i, weight: 1 },
      { regex: /domain controller/i, weight: 2 },
      { regex: /\bbloodhound\b/i, weight: 2 },
      { regex: /\bpowerview\b/i, weight: 2 },
      { regex: /\bdcsync\b/i, weight: 3 },
      { regex: /\badcs\b/i, weight: 2 },
      { regex: /\bkerberoast\b/i, weight: 2 },
      { regex: /\basreproast\b/i, weight: 2 },
      { regex: /域控|域内/i, weight: 2 },
    ],
  },
  {
    tag: "Kerberos",
    source: "body",
    minScore: 3,
    patterns: [
      { regex: /\bkerberos\b/i, weight: 2 },
      { regex: /\bkerberoast\b/i, weight: 3 },
      { regex: /\basreproast\b/i, weight: 3 },
      { regex: /\brubeus\b/i, weight: 2 },
      { regex: /silver ticket/i, weight: 2 },
      { regex: /golden ticket/i, weight: 2 },
      { regex: /\bspn\b/i, weight: 1 },
      { regex: /ticket/i, weight: 1 },
    ],
  },
  {
    tag: "ADCS",
    source: "body",
    minScore: 2,
    patterns: [
      { regex: /\badcs\b/i, weight: 3 },
      { regex: /\bcertipy\b/i, weight: 2 },
      { regex: /\bcertify\b/i, weight: 2 },
      { regex: /certificate services/i, weight: 2 },
      { regex: /shadow credentials/i, weight: 2 },
      { regex: /\besc\d+\b/i, weight: 2 },
    ],
  },
  {
    tag: "Password Attacks",
    source: "combined",
    minScore: 3,
    patterns: [
      { regex: /password attacks?/i, weight: 3 },
      { regex: /brute[- ]?force/i, weight: 2 },
      { regex: /\bhydra\b/i, weight: 2 },
      { regex: /\bhashcat\b/i, weight: 2 },
      { regex: /john the ripper/i, weight: 2 },
      { regex: /\brockyou\b/i, weight: 1 },
      { regex: /\bwordlist\b/i, weight: 1 },
      { regex: /\bcewl\b/i, weight: 2 },
      { regex: /password spray/i, weight: 2 },
      { regex: /字典攻击|口令爆破|爆破/i, weight: 2 },
    ],
  },
  {
    tag: "Credential Dumping",
    source: "body",
    minScore: 3,
    patterns: [
      { regex: /\bmimikatz\b/i, weight: 2 },
      { regex: /\bsecretsdump\b/i, weight: 2 },
      { regex: /\blsassy\b/i, weight: 2 },
      { regex: /\blsass\b/i, weight: 2 },
      { regex: /\bntds\.dit\b/i, weight: 2 },
      { regex: /\bdpapi\b/i, weight: 2 },
      { regex: /\bhashdump\b/i, weight: 2 },
      { regex: /\bsam\b/i, weight: 1 },
    ],
  },
  {
    tag: "Lateral Movement",
    source: "body",
    minScore: 3,
    patterns: [
      { regex: /lateral movement/i, weight: 3 },
      { regex: /\bpivot(?:ing)?\b/i, weight: 2 },
      { regex: /\bchisel\b/i, weight: 2 },
      { regex: /\bligolo\b/i, weight: 2 },
      { regex: /proxychains/i, weight: 1 },
      { regex: /port forwarding?/i, weight: 1 },
      { regex: /横向移动|端口转发/i, weight: 2 },
    ],
  },
  {
    tag: "Persistence",
    source: "combined",
    minScore: 2,
    patterns: [
      { regex: /\bpersistence\b/i, weight: 3 },
      { regex: /\bschtasks\b/i, weight: 2 },
      { regex: /scheduled tasks?/i, weight: 2 },
      { regex: /startup folder/i, weight: 2 },
      { regex: /run key/i, weight: 2 },
      { regex: /注册表启动|持久化|计划任务/i, weight: 2 },
    ],
  },
  {
    tag: "C2",
    source: "title",
    minScore: 2,
    patterns: [
      { regex: /\bc2\b/i, weight: 2 },
      { regex: /command and control/i, weight: 2 },
      { regex: /cobalt strike/i, weight: 2 },
      { regex: /\bsliver\b/i, weight: 2 },
      { regex: /\bbeacon\b/i, weight: 1 },
      { regex: /\bmythic\b/i, weight: 2 },
    ],
  },
  {
    tag: "Phishing",
    source: "title",
    minScore: 2,
    patterns: [
      { regex: /spear[- ]?phishing/i, weight: 2 },
      { regex: /\bphishing\b/i, weight: 2 },
      { regex: /\bgophish\b/i, weight: 2 },
      { regex: /钓鱼/i, weight: 2 },
    ],
  },
  {
    tag: "Threat Intel",
    source: "title",
    minScore: 2,
    patterns: [
      { regex: /threat intelligence?/i, weight: 3 },
      { regex: /\bthreat intel\b/i, weight: 3 },
      { regex: /intelligence cycle/i, weight: 2 },
      { regex: /\bioc\b/i, weight: 1 },
      { regex: /mitre att&ck|mitre attack/i, weight: 1 },
      { regex: /diamond model/i, weight: 1 },
    ],
  },
  {
    tag: "OSINT",
    source: "body",
    minScore: 2,
    patterns: [
      { regex: /\bosint\b/i, weight: 2 },
      { regex: /\btheharvester\b/i, weight: 2 },
      { regex: /\bshodan\b/i, weight: 2 },
      { regex: /\bmaltego\b/i, weight: 2 },
      { regex: /crt\.sh/i, weight: 2 },
      { regex: /\bwhois\b/i, weight: 1 },
    ],
  },
  {
    tag: "SQL Injection",
    source: "body",
    minScore: 2,
    patterns: [
      { regex: /sql injection/i, weight: 2 },
      { regex: /\bsqli\b/i, weight: 2 },
      { regex: /\bsqlmap\b/i, weight: 2 },
      { regex: /union select/i, weight: 1 },
    ],
  },
  {
    tag: "XSS",
    source: "body",
    minScore: 2,
    patterns: [
      { regex: /cross-site scripting/i, weight: 2 },
      { regex: /\bxss\b/i, weight: 2 },
    ],
  },
  {
    tag: "File Upload",
    source: "body",
    minScore: 2,
    patterns: [
      { regex: /file upload/i, weight: 2 },
      { regex: /upload bypass/i, weight: 2 },
      { regex: /上传漏洞/i, weight: 2 },
    ],
  },
  {
    tag: "LFI",
    source: "body",
    minScore: 2,
    patterns: [
      { regex: /local file inclusion/i, weight: 2 },
      { regex: /\blfi\b/i, weight: 2 },
    ],
  },
  {
    tag: "SSRF",
    source: "body",
    minScore: 2,
    patterns: [
      { regex: /\bssrf\b/i, weight: 2 },
    ],
  },
  {
    tag: "SSTI",
    source: "body",
    minScore: 2,
    patterns: [
      { regex: /server-side template injection/i, weight: 2 },
      { regex: /\bssti\b/i, weight: 2 },
    ],
  },
  {
    tag: "XXE",
    source: "body",
    minScore: 2,
    patterns: [
      { regex: /xml external entity/i, weight: 2 },
      { regex: /\bxxe\b/i, weight: 2 },
    ],
  },
  {
    tag: "Command Injection",
    source: "body",
    minScore: 2,
    patterns: [
      { regex: /command injection/i, weight: 2 },
      { regex: /os command injection/i, weight: 2 },
      { regex: /命令注入/i, weight: 2 },
    ],
  },
  {
    tag: "RCE",
    source: "body",
    minScore: 4,
    patterns: [
      { regex: /remote code execution/i, weight: 2 },
      { regex: /\brce\b/i, weight: 2 },
      { regex: /代码执行/i, weight: 2 },
    ],
  },
  {
    tag: "Deserialization",
    source: "body",
    minScore: 2,
    patterns: [
      { regex: /deserialization/i, weight: 2 },
      { regex: /php object injection/i, weight: 2 },
      { regex: /反序列化/i, weight: 2 },
    ],
  },
  {
    tag: "WordPress",
    source: "body",
    minScore: 3,
    patterns: [
      { regex: /\bwordpress\b/i, weight: 2 },
      { regex: /wp-admin/i, weight: 2 },
      { regex: /wp-content/i, weight: 1 },
    ],
  },
  {
    tag: "Docker",
    source: "body",
    minScore: 3,
    patterns: [
      { regex: /\bdocker\b/i, weight: 2 },
      { regex: /docker\.sock/i, weight: 2 },
      { regex: /docker-compose/i, weight: 1 },
    ],
  },
  {
    tag: "Kubernetes",
    source: "body",
    minScore: 3,
    patterns: [
      { regex: /\bkubernetes\b/i, weight: 2 },
      { regex: /\bk8s\b/i, weight: 2 },
      { regex: /\bkubectl\b/i, weight: 2 },
    ],
  },
  {
    tag: "Reverse Engineering",
    source: "combined",
    minScore: 3,
    patterns: [
      { regex: /reverse engineering/i, weight: 2 },
      { regex: /\bghidra\b/i, weight: 2 },
      { regex: /\bida\b/i, weight: 2 },
      { regex: /逆向/i, weight: 2 },
      { regex: /decompile/i, weight: 1 },
    ],
  },
  {
    tag: "Exploit Development",
    source: "combined",
    minScore: 2,
    patterns: [
      { regex: /buffer overflow/i, weight: 2 },
      { regex: /\bshellcode\b/i, weight: 2 },
      { regex: /\brop\b/i, weight: 2 },
      { regex: /\begghunter\b/i, weight: 2 },
      { regex: /\bseh\b/i, weight: 2 },
      { regex: /stack overflow/i, weight: 2 },
      { regex: /exploit development/i, weight: 2 },
    ],
  },
  {
    tag: "Windows",
    source: "title",
    minScore: 2,
    patterns: [
      { regex: /\bwindows\b/i, weight: 2 },
    ],
  },
  {
    tag: "Competition",
    source: "combined",
    minScore: 2,
    patterns: [
      { regex: /\bctf\b/i, weight: 2 },
      { regex: /比赛|竞赛|挑战赛|铁人三项/i, weight: 2 },
    ],
  },
  {
    tag: "Internship",
    source: "combined",
    minScore: 2,
    patterns: [
      { regex: /\binternship\b/i, weight: 2 },
      { regex: /实习/i, weight: 2 },
    ],
  },
  {
    tag: "Red Team",
    source: "body",
    minScore: 3,
    patterns: [
      { regex: /red team/i, weight: 2 },
      { regex: /红队|攻防演练/i, weight: 2 },
    ],
  },
  {
    tag: "Blue Team",
    source: "body",
    minScore: 3,
    patterns: [
      { regex: /blue team/i, weight: 2 },
      { regex: /蓝队/i, weight: 2 },
    ],
  },
  {
    tag: "Incident Response",
    source: "body",
    minScore: 3,
    patterns: [
      { regex: /incident response/i, weight: 2 },
      { regex: /应急响应|应急处置/i, weight: 2 },
    ],
  },
  {
    tag: "Security Operations",
    source: "body",
    minScore: 3,
    patterns: [
      { regex: /security operations/i, weight: 2 },
      { regex: /\bsoc\b/i, weight: 2 },
      { regex: /安全值守|安服/i, weight: 2 },
    ],
  },
];

function walkMarkdownFiles(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...walkMarkdownFiles(fullPath));
      continue;
    }
    if (entry.isFile() && fullPath.endsWith(".md")) {
      files.push(fullPath);
    }
  }

  return files;
}

function parseMarkdownFile(content) {
  const match = content.match(FRONTMATTER_PATTERN);
  if (!match) return null;

  return {
    frontmatterRaw: match[1],
    body: match[2],
  };
}

function parseScalar(value) {
  const trimmed = String(value ?? "").trim();
  if (!trimmed) return "";

  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1);
  }

  if (trimmed === "true") return true;
  if (trimmed === "false") return false;
  return trimmed;
}

function parseSimpleFrontmatter(frontmatter) {
  const lines = frontmatter.split(/\r?\n/);
  const data = {};

  let index = 0;
  while (index < lines.length) {
    const line = lines[index];
    const keyMatch = line.match(/^([A-Za-z0-9_-]+):\s*(.*)$/);

    if (!keyMatch) {
      index += 1;
      continue;
    }

    const key = keyMatch[1];
    const value = keyMatch[2] ?? "";

    if (value.trim() === "") {
      const arrayValues = [];
      let cursor = index + 1;

      while (cursor < lines.length && !/^[A-Za-z0-9_-]+:\s*/.test(lines[cursor])) {
        const itemMatch = lines[cursor].match(/^\s*-\s*(.*)$/);
        if (itemMatch) {
          arrayValues.push(parseScalar(itemMatch[1]));
        }
        cursor += 1;
      }

      data[key] = arrayValues;
      index = cursor;
      continue;
    }

    data[key] = parseScalar(value);
    index += 1;
  }

  return data;
}

function normalize(value) {
  return String(value ?? "")
    .toLowerCase()
    .replace(/\s+/g, " ")
    .trim();
}

function uniqueTags(tags) {
  const seen = new Set();
  const result = [];

  for (const tag of tags) {
    const value = String(tag ?? "").trim();
    if (!value) continue;
    const key = normalize(value);
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(value);
  }

  return result;
}

function formatTagValue(tag) {
  const value = String(tag ?? "");
  const needsQuote =
    /^[\s]|[\s]$/.test(value) ||
    /[:#,[\]{}&*!?|>'"%@`]/.test(value) ||
    /^(true|false|null|yes|no|on|off|~|[-+]?[0-9.]+)$/.test(value.toLowerCase());

  if (!needsQuote) return value;
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function replaceTagsSection(frontmatter, tags, eol) {
  const lines = frontmatter.split(/\r?\n/);
  const topKeyPattern = /^[A-Za-z0-9_-]+:\s*/;
  const tagLines = ["tags:", ...tags.map((tag) => `  - ${formatTagValue(tag)}`)];
  const sectionStart = lines.findIndex((line) => /^tags:\s*(?:#.*)?$/.test(line));

  if (sectionStart >= 0) {
    let sectionEnd = lines.length;
    for (let index = sectionStart + 1; index < lines.length; index += 1) {
      if (topKeyPattern.test(lines[index])) {
        sectionEnd = index;
        break;
      }
    }

    lines.splice(sectionStart, sectionEnd - sectionStart, ...tagLines);
    return lines.join(eol);
  }

  const categoriesStart = lines.findIndex((line) => /^categories:\s*(?:#.*)?$/.test(line));
  if (categoriesStart >= 0) {
    let categoriesEnd = lines.length;
    for (let index = categoriesStart + 1; index < lines.length; index += 1) {
      if (topKeyPattern.test(lines[index])) {
        categoriesEnd = index;
        break;
      }
    }

    lines.splice(categoriesEnd, 0, ...tagLines);
    return lines.join(eol);
  }

  lines.push(...tagLines);
  return lines.join(eol);
}

function countMatches(text, regex) {
  const flags = regex.flags.includes("g") ? regex.flags : `${regex.flags}g`;
  const matcher = new RegExp(regex.source, flags);
  return [...text.matchAll(matcher)].length;
}

function buildSources(metadata, body) {
  const title = [metadata.title, metadata.description]
    .filter(Boolean)
    .map((value) => String(value))
    .join("\n");

  return {
    title,
    body,
    combined: `${title}\n${body}`.trim(),
  };
}

function scoreTagDefinition(definition, sources) {
  const sourceText = sources[definition.source] ?? sources.combined;
  let score = 0;

  for (const pattern of definition.patterns) {
    const count = Math.min(countMatches(sourceText, pattern.regex), 3);
    score += count * (pattern.weight ?? 1);
  }

  return score;
}

function hasTag(tags, tagName) {
  return tags.some((tag) => normalize(tag) === normalize(tagName));
}

function shouldSkipDefinition(definition, baseTags) {
  if (definition.tag === "Windows" && hasTag(baseTags, "Windows Machine")) {
    return true;
  }

  return false;
}

const gitShowCache = new Map();
const gitHistoryCache = new Map();
const historicalBodyCache = new Map();

function gitShow(revision, repoRelativePath) {
  const cacheKey = `${revision}:${repoRelativePath}`;
  if (gitShowCache.has(cacheKey)) {
    return gitShowCache.get(cacheKey);
  }

  try {
    const content = execFileSync("git", ["-C", REPO_ROOT, "show", `${revision}:${repoRelativePath}`], {
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
    });
    gitShowCache.set(cacheKey, content);
    return content;
  } catch {
    gitShowCache.set(cacheKey, null);
    return null;
  }
}

function gitHistory(repoRelativePath) {
  if (gitHistoryCache.has(repoRelativePath)) {
    return gitHistoryCache.get(repoRelativePath);
  }

  try {
    const output = execFileSync(
      "git",
      ["-C", REPO_ROOT, "log", "--follow", "--format=%H", "--", repoRelativePath],
      {
        encoding: "utf8",
        maxBuffer: 16 * 1024 * 1024,
      },
    );
    const revisions = output
      .split(/\r?\n/)
      .map((value) => value.trim())
      .filter(Boolean);
    gitHistoryCache.set(repoRelativePath, revisions);
    return revisions;
  } catch {
    gitHistoryCache.set(repoRelativePath, []);
    return [];
  }
}

function getHistoricalPlaintextBody(repoRelativePath) {
  if (historicalBodyCache.has(repoRelativePath)) {
    return historicalBodyCache.get(repoRelativePath);
  }

  for (const revision of gitHistory(repoRelativePath)) {
    const content = gitShow(revision, repoRelativePath);
    if (!content) continue;

    const parsed = parseMarkdownFile(content);
    if (!parsed) continue;

    const metadata = parseSimpleFrontmatter(parsed.frontmatterRaw);
    if (metadata.encryptionContent || metadata.passwordHash) continue;
    if (!parsed.body.trim()) continue;

    historicalBodyCache.set(repoRelativePath, parsed.body);
    return parsed.body;
  }

  historicalBodyCache.set(repoRelativePath, "");
  return "";
}

function getBaseTags(repoRelativePath, currentMetadata) {
  const headContent = gitShow("HEAD", repoRelativePath);
  if (headContent) {
    const parsed = parseMarkdownFile(headContent);
    if (parsed) {
      const headMetadata = parseSimpleFrontmatter(parsed.frontmatterRaw);
      if (Array.isArray(headMetadata.tags)) {
        return headMetadata.tags.map((tag) => String(tag));
      }
    }
  }

  return Array.isArray(currentMetadata.tags) ? currentMetadata.tags.map((tag) => String(tag)) : [];
}

function getAnalysisBody(repoRelativePath, currentMetadata, currentBody) {
  if (currentMetadata.encryptionContent || currentMetadata.passwordHash) {
    const historicalBody = getHistoricalPlaintextBody(repoRelativePath);
    if (historicalBody) return historicalBody;
  }

  return currentBody;
}

function deriveTags(metadata, analysisBody, baseTags) {
  const sources = buildSources(metadata, analysisBody);

  return TAG_DEFINITIONS
    .filter((definition) => !shouldSkipDefinition(definition, baseTags))
    .map((definition) => ({
      tag: definition.tag,
      score: scoreTagDefinition(definition, sources),
      minScore: definition.minScore,
    }))
    .filter((entry) => entry.score >= entry.minScore && !hasTag(baseTags, entry.tag))
    .sort((left, right) => right.score - left.score || left.tag.localeCompare(right.tag))
    .map((entry) => entry.tag);
}

const files = walkMarkdownFiles(BLOG_DIR);
let changedCount = 0;
const addedTagFrequency = new Map();

for (const file of files) {
  const raw = fs.readFileSync(file, "utf8");
  const parsed = parseMarkdownFile(raw);
  if (!parsed) continue;

  const repoRelativePath = path.relative(REPO_ROOT, file).split(path.sep).join("/");
  const metadata = parseSimpleFrontmatter(parsed.frontmatterRaw);
  const baseTags = uniqueTags(getBaseTags(repoRelativePath, metadata));
  const analysisBody = getAnalysisBody(repoRelativePath, metadata, parsed.body);
  const derivedTags = deriveTags(metadata, analysisBody, baseTags);
  const mergedTags = uniqueTags([...baseTags, ...derivedTags]);

  const existingTags = Array.isArray(metadata.tags) ? metadata.tags.map((tag) => String(tag)) : [];
  const changed =
    mergedTags.length !== existingTags.length ||
    mergedTags.some((tag, index) => tag !== existingTags[index]);

  if (!changed) continue;

  const eol = raw.includes("\r\n") ? "\r\n" : "\n";
  const updatedFrontmatter = replaceTagsSection(parsed.frontmatterRaw, mergedTags, eol);
  const updatedContent = raw.replace(parsed.frontmatterRaw, updatedFrontmatter);

  fs.writeFileSync(file, updatedContent, "utf8");
  changedCount += 1;

  for (const tag of mergedTags) {
    if (!hasTag(baseTags, tag)) {
      addedTagFrequency.set(tag, (addedTagFrequency.get(tag) ?? 0) + 1);
    }
  }
}

const summary = [...addedTagFrequency.entries()]
  .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
  .slice(0, 20)
  .map(([tag, count]) => `${tag}:${count}`)
  .join(", ");

console.log(`Updated files: ${changedCount}`);
console.log(`Top added tags: ${summary}`);
