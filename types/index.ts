export type StageStatus = "pending" | "running" | "complete" | "error";

export type StageId =
  | "advisory_parsed"
  | "repository_scanned"
  | "reachability_analyzed"
  | "patch_generated"
  | "tests_run"
  | "pull_request_drafted";

export interface Stage {
  id: StageId;
  label: string;
  status: StageStatus;
  message?: string;
}

export interface SSEPayload {
  patch: string;
  prTitle: string;
  prDescription: string;
}

export interface SSEEvent {
  stage: StageId | "error";
  status: StageStatus;
  message?: string;
  data?: SSEPayload;
}

export interface PipelineResult {
  patch: string;
  prTitle: string;
  prDescription: string;
}
