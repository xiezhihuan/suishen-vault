// 检查验收编号：PRD 中定义唯一；其他文档、代码引用的编号都存在；必需文档齐全。
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { root } from "./env.mjs";

const required = ["调研.md", "PRD.md", "设计.md", "威胁模型.md", "未验证项.md"].map((f) => join("docs", f));
const errors = required.filter((f) => !existsSync(join(root, f))).map((f) => `缺少文档：${f}`);
const ID = /\b(?:AC|US|F)-[A-Z]{3}-\d{2}\b/g;

const skip = new Set(["node_modules", "target", "dist", "gen", ".git", "icons"]);
function* walk(dir) {
  for (const name of readdirSync(dir)) {
    if (skip.has(name)) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* walk(p);
    else if (/\.(md|rs|ts|tsx|mjs)$/.test(name)) yield p;
  }
}

const defs = new Map();
if (existsSync(join(root, "docs/PRD.md"))) {
  for (const line of readFileSync(join(root, "docs/PRD.md"), "utf8").split("\n")) {
    // 定义行：表格首列就是编号
    const m = line.match(/^\|\s*((?:AC|US|F)-[A-Z]{3}-\d{2})\s*\|/);
    if (!m) continue;
    if (defs.has(m[1])) errors.push(`PRD 编号重复：${m[1]}`);
    defs.set(m[1], true);
  }
}
let refs = 0;
for (const p of walk(root)) {
  for (const m of readFileSync(p, "utf8").matchAll(ID)) {
    refs += 1;
    if (!defs.has(m[0])) errors.push(`${relative(root, p)} 引用了不存在的编号 ${m[0]}`);
  }
}

for (const f of required.filter((f) => existsSync(join(root, f)))) {
  const text = readFileSync(join(root, f), "utf8");
  if (/待定|待讨论|TBD|TODO/.test(text)) errors.push(`${f} 含未决标记`);
  if ((text.match(/^```/gm) ?? []).length % 2) errors.push(`${f} 代码块未闭合`);
}

if (errors.length) {
  for (const e of errors) console.error(e);
  process.exit(1);
}
const ac = [...defs.keys()].filter((k) => k.startsWith("AC-")).length;
console.log(`验收编号 ${ac} 条，全部编号 ${defs.size} 个，引用 ${refs} 处，均有效。`);
