// Tracepath TypeScript SDK — auditable AI agent middleware
// Apache 2.0

export interface AuditStep {
  session_id: string;
  agent_id: string;
  agent_type?: string;
  step_number: number;
  tool_name: string;
  tool_input: unknown;
  tool_output: unknown;
  timestamp: string;
}

export interface PolicyDecision {
  allowed: boolean;
  denials: string[];
}

export interface AuditResponse {
  status: "recorded" | "denied";
  signature: string;
  policy_decision?: PolicyDecision;
}

export interface QueryParams {
  session_id?: string;
  agent_id?: string;
  tool_name?: string;
  limit?: number;
  offset?: number;
}

export interface AuditEvent {
  id: string;
  session_id: string;
  agent_id: string;
  agent_type?: string;
  step_number: number;
  tool_name: string;
  signature: string;
  policy_decision?: string;
  created_at: string;
}

export interface QueryResponse {
  events: AuditEvent[];
  count: number;
  limit: number;
  offset: number;
}

export class AuditClient {
  private baseUrl: string;
  private sessionId: string;
  private agentId: string;
  private agentType?: string;
  private stepCounter: number;

  constructor(options: {
    baseUrl?: string;
    sessionId: string;
    agentId: string;
    agentType?: string;
  }) {
    this.baseUrl = options.baseUrl ?? "http://localhost:9001";
    this.sessionId = options.sessionId;
    this.agentId = options.agentId;
    this.agentType = options.agentType;
    this.stepCounter = 0;
  }

  /**
   * Record an audit step. Returns the signed response with policy decision.
   */
  async recordStep(toolName: string, toolInput: unknown, toolOutput: unknown): Promise<AuditResponse> {
    this.stepCounter++;

    const body: AuditStep = {
      session_id: this.sessionId,
      agent_id: this.agentId,
      agent_type: this.agentType,
      step_number: this.stepCounter,
      tool_name: toolName,
      tool_input: toolInput,
      tool_output: toolOutput,
      timestamp: new Date().toISOString(),
    };

    const response = await fetch(`${this.baseUrl}/audit/step`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`Tracepath audit failed (${response.status}): ${errorBody}`);
    }

    return response.json() as Promise<AuditResponse>;
  }

  /**
   * Query audit events with optional filters.
   */
  async queryEvents(params?: QueryParams): Promise<QueryResponse> {
    const searchParams = new URLSearchParams();
    if (params?.session_id) searchParams.set("session_id", params.session_id);
    if (params?.agent_id) searchParams.set("agent_id", params.agent_id);
    if (params?.tool_name) searchParams.set("tool_name", params.tool_name);
    if (params?.limit) searchParams.set("limit", String(params.limit));
    if (params?.offset) searchParams.set("offset", String(params.offset));

    const url = `${this.baseUrl}/audit/events?${searchParams.toString()}`;
    const response = await fetch(url);

    if (!response.ok) {
      throw new Error(`Tracepath query failed (${response.status})`);
    }

    return response.json() as Promise<QueryResponse>;
  }

  /**
   * Check gateway and policy health.
   */
  async health(): Promise<{ status: string; service: string; version: string }> {
    const response = await fetch(`${this.baseUrl}/health`);
    return response.json() as Promise<{ status: string; service: string; version: string }>;
  }
}

export default AuditClient;
