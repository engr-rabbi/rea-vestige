import { mkdir, readFile, writeFile, rename, readdir } from "node:fs/promises";
import path from "node:path";
import {
  evidenceSchema,
  verifyEvidence,
  type Evidence,
} from "../domain/evidence.js";
import {
  findingSchema,
  verifyFinding,
  type Finding,
} from "../domain/finding.js";
import { internalError } from "../errors/errors.js";

export interface EvidenceAppendix {
  evidence: Evidence[];
  findings: Finding[];
}

/**
 * Content-addressed evidence store.
 *
 * Layout:
 *   <dataDir>/evidence/objects/<xx>/<sha256>.json   — immutable evidence objects
 *   <dataDir>/evidence/findings/<artifactId>.json   — finding records per artifact
 *   <dataDir>/evidence/index.jsonl                  — append-only id → kind index
 *
 * Objects are addressed by the SHA-256 of their canonical JSON, so identical
 * evidence from repeated analyses is stored once and re-verification is cheap.
 */
export class EvidenceStore {
  private readonly objectsDir: string;
  private readonly findingsDir: string;
  private readonly indexPath: string;

  constructor(dataDir: string) {
    const root = path.join(dataDir, "evidence");
    this.objectsDir = path.join(root, "objects");
    this.findingsDir = path.join(root, "findings");
    this.indexPath = path.join(root, "index.jsonl");
  }

  private objectPath(evidenceId: string): string {
    return path.join(this.objectsDir, evidenceId.slice(3, 5), `${evidenceId}.json`);
  }

  /** Store evidence; returns true when the record was new. */
  async putEvidence(evidence: Evidence): Promise<boolean> {
    evidenceSchema.parse(evidence);
    if (!verifyEvidence(evidence)) {
      throw internalError(
        `Evidence identity mismatch for ${evidence.evidenceId}; refusing to store tampered record.`,
      );
    }
    const body = JSON.stringify(evidence, null, 2);
    const file = this.objectPath(evidence.evidenceId);
    try {
      await readFile(file, "utf8");
      return false; // already present (content-addressed identity)
    } catch {
      /* new object */
    }
    await mkdir(path.dirname(file), { recursive: true });
    const tmp = `${file}.tmp`;
    await writeFile(tmp, body, "utf8");
    await rename(tmp, file);
    await mkdir(path.dirname(this.indexPath), { recursive: true });
    const indexLine = `${JSON.stringify({
      evidenceId: evidence.evidenceId,
      artifactId: evidence.artifactId,
      kind: evidence.kind,
      confidence: evidence.confidence,
      at: evidence.collectedAt,
    })}\n`;
    await writeFile(this.indexPath, indexLine, { flag: "a" });
    return true;
  }

  async getEvidence(evidenceId: string): Promise<Evidence | undefined> {
    try {
      const body = await readFile(this.objectPath(evidenceId), "utf8");
      const parsed = evidenceSchema.parse(JSON.parse(body));
      if (!verifyEvidence(parsed)) return undefined;
      return parsed;
    } catch {
      return undefined;
    }
  }

  /** Persist findings for an artifact (replaces the artifact's finding set). */
  async putFindings(artifactId: string, findings: Finding[]): Promise<void> {
    for (const f of findings) {
      findingSchema.parse(f);
      if (!verifyFinding(f)) {
        throw internalError(
          `Finding identity mismatch for ${f.findingId}; refusing to store tampered record.`,
        );
      }
    }
    await mkdir(this.findingsDir, { recursive: true });
    const file = path.join(this.findingsDir, `${artifactId}.json`);
    const tmp = `${file}.tmp`;
    await writeFile(tmp, JSON.stringify(findings, null, 2), "utf8");
    await rename(tmp, file);
  }

  async getFindings(artifactId: string): Promise<Finding[]> {
    try {
      const body = await readFile(
        path.join(this.findingsDir, `${artifactId}.json`),
        "utf8",
      );
      const parsed: unknown = JSON.parse(body);
      if (!Array.isArray(parsed)) return [];
      return parsed
        .map((f) => findingSchema.parse(f))
        .filter((f) => verifyFinding(f));
    } catch {
      return [];
    }
  }

  /** Artifacts that have at least one stored finding set. */
  async artifactsWithFindings(): Promise<string[]> {
    try {
      const files = await readdir(this.findingsDir);
      return files
        .filter((f) => f.endsWith(".json"))
        .map((f) => f.slice(0, -".json".length));
    } catch {
      return [];
    }
  }
}
