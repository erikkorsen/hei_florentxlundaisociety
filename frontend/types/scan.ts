export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "PASS";
export type Category = "secrets" | "ports" | "ssl" | "admin" | "firewall" | "github" | "headers" | "dns" | "cookies" | "cors";

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  affected: string;
  fix: string;
  category: Category;
}

export interface ScanResponse {
  target_url: string;
  github_url: string | null;
  scan_duration_seconds: number;
  summary: Record<Severity, number>;
  findings: Finding[];
}

export interface ScanRequest {
  url: string;
  github_url?: string;
}
