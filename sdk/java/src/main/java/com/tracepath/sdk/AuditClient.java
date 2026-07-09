// Tracepath Java SDK — auditable AI agent middleware
// Apache 2.0

package com.tracepath.sdk;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * Main entry point for the Tracepath audit SDK.
 *
 * <pre>{@code
 * AuditClient client = new AuditClient("my-session", "my-agent");
 * AuditResponse resp = client.recordStep("read_file", input, output);
 * }</pre>
 */
public class AuditClient {

    private static final Gson GSON = new GsonBuilder().create();
    private static final HttpClient HTTP = HttpClient.newHttpClient();

    private final String baseUrl;
    private final String sessionId;
    private final String agentId;
    private final String agentType;
    private int stepCounter;

    public AuditClient(String sessionId, String agentId) {
        this("http://localhost:9001", sessionId, agentId, null);
    }

    public AuditClient(String baseUrl, String sessionId, String agentId, String agentType) {
        this.baseUrl = Objects.requireNonNull(baseUrl);
        this.sessionId = Objects.requireNonNull(sessionId);
        this.agentId = Objects.requireNonNull(agentId);
        this.agentType = agentType;
        this.stepCounter = 0;
    }

    /**
     * Record an audit step. Returns the signed response with policy decision.
     */
    public AuditResponse recordStep(String toolName, Object toolInput, Object toolOutput)
            throws IOException, InterruptedException {
        stepCounter++;

        AuditStep step = new AuditStep();
        step.sessionId = sessionId;
        step.agentId = agentId;
        step.agentType = agentType;
        step.stepNumber = stepCounter;
        step.toolName = toolName;
        step.toolInput = toolInput;
        step.toolOutput = toolOutput;
        step.timestamp = Instant.now().toString();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/audit/step"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(GSON.toJson(step)))
                .build();

        HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() >= 400) {
            throw new IOException("Tracepath audit failed (" + response.statusCode() + "): " + response.body());
        }

        return GSON.fromJson(response.body(), AuditResponse.class);
    }

    /**
     * Query audit events with optional filters.
     */
    public QueryResponse queryEvents(QueryParams params) throws IOException, InterruptedException {
        StringBuilder url = new StringBuilder(baseUrl + "/audit/events?");
        if (params != null) {
            if (params.sessionId != null) url.append("session_id=").append(params.sessionId).append("&");
            if (params.agentId != null) url.append("agent_id=").append(params.agentId).append("&");
            if (params.toolName != null) url.append("tool_name=").append(params.toolName).append("&");
            if (params.limit != null) url.append("limit=").append(params.limit).append("&");
            if (params.offset != null) url.append("offset=").append(params.offset).append("&");
        }

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url.toString()))
                .GET()
                .build();

        HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() >= 400) {
            throw new IOException("Tracepath query failed (" + response.statusCode() + ")");
        }

        return GSON.fromJson(response.body(), QueryResponse.class);
    }

    // ── Data classes ──

    public static class AuditStep {
        @SerializedName("session_id") String sessionId;
        @SerializedName("agent_id") String agentId;
        @SerializedName("agent_type") String agentType;
        @SerializedName("step_number") int stepNumber;
        @SerializedName("tool_name") String toolName;
        @SerializedName("tool_input") Object toolInput;
        @SerializedName("tool_output") Object toolOutput;
        String timestamp;
    }

    public static class AuditResponse {
        String status;
        String signature;
        @SerializedName("policy_decision") PolicyDecision policyDecision;
    }

    public static class PolicyDecision {
        boolean allowed;
        List<String> denials;
    }

    public static class QueryParams {
        @SerializedName("session_id") String sessionId;
        @SerializedName("agent_id") String agentId;
        @SerializedName("tool_name") String toolName;
        Integer limit;
        Integer offset;

        public QueryParams() {}

        public QueryParams sessionId(String v) { this.sessionId = v; return this; }
        public QueryParams agentId(String v) { this.agentId = v; return this; }
        public QueryParams toolName(String v) { this.toolName = v; return this; }
        public QueryParams limit(int v) { this.limit = v; return this; }
        public QueryParams offset(int v) { this.offset = v; return this; }
    }

    public static class QueryResponse {
        List<AuditEvent> events;
        int count;
        int limit;
        int offset;
    }

    public static class AuditEvent {
        String id;
        @SerializedName("session_id") String sessionId;
        @SerializedName("agent_id") String agentId;
        @SerializedName("agent_type") String agentType;
        @SerializedName("step_number") int stepNumber;
        @SerializedName("tool_name") String toolName;
        String signature;
        @SerializedName("policy_decision") String policyDecision;
        @SerializedName("created_at") String createdAt;
    }
}
