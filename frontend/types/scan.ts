export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "PASS";
export type Category = "secrets" | "ports" | "ssl" | "admin" | "firewall" | "github" | "headers" | "dns" | "cookies" | "cors" | "subdomains" | "breach";

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

export interface GroupedFinding {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  affected: string[];
  fix: string;
  category: Category;
  count: number;
  raw_ids: string[];
  likely_false_positive: boolean;
  plain_english: string;
  business_impact: string;
}

export interface AnalysisResponse {
  target_url: string;
  summary: string | null;
  priority_actions: string[];
  grouped_findings: GroupedFinding[];
  pass_count: number;
  ai_powered: boolean;
  raw_findings: Finding[];
}

export interface AnalyseRequest {
  target_url: string;
  github_url?: string;
  findings: Finding[];
}
