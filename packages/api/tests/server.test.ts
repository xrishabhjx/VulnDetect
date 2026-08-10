import { describe, it, expect } from "vitest";
import request from "supertest";
import { app, parseRepoInput } from "../src/server.js";

// ─── Repo URL parsing (unit) ────────────────────────────────────────────────

describe("parseRepoInput", () => {
  it.each<[string, string, string]>([
    ["facebook/react",                          "facebook",  "react"],
    ["vercel/next.js",                          "vercel",    "next.js"],
    ["https://github.com/expressjs/express",    "expressjs", "express"],
    ["https://github.com/expressjs/express.git","expressjs", "express"],
    ["http://github.com/torvalds/linux",        "torvalds",  "linux"],
    ["github.com/nodejs/node",                  "nodejs",    "node"],
    ["git@github.com:owner/name.git",           "owner",     "name"],
  ])("accepts %s", (input, owner, repo) => {
    expect(parseRepoInput(input)).toEqual({ owner, repo });
  });

  it.each<[unknown]>([
    [""],
    [null],
    [undefined],
    [123],
    ["not-a-repo"],
    ["facebook"],
    ["facebook/"],
    ["a b/c d"],
    ["-bad-/repo"],
    ["bad-/repo"],
    ["owner/repo$bad"],
  ])("rejects %#", (input) => {
    expect(parseRepoInput(input)).toBeNull();
  });
});

// ─── HTTP endpoints (integration) ───────────────────────────────────────────

describe("GET /api/health", () => {
  it("returns 200 with service metadata", async () => {
    const res = await request(app).get("/api/health");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ status: "ok", service: "vuln-shield-api" });
    expect(typeof res.body.timestamp).toBe("string");
  });
});

describe("POST /api/scan — input validation", () => {
  it("rejects empty body with 400", async () => {
    const res = await request(app).post("/api/scan").send({});
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/repoUrl/i);
  });

  it("rejects malformed repoUrl with 400", async () => {
    const res = await request(app)
      .post("/api/scan")
      .send({ repoUrl: "not a real repo" });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid/i);
  });

  it("rejects non-string repoUrl with 400", async () => {
    const res = await request(app)
      .post("/api/scan")
      .send({ repoUrl: 12345 });
    expect(res.status).toBe(400);
  });

  it("rejects unsupported HTTP method with 404", async () => {
    // Express 5 returns 404 for unknown methods rather than 405.
    const res = await request(app).put("/api/scan");
    expect([404, 405]).toContain(res.status);
  });
});

describe("POST /api/analyze — input validation", () => {
  it("rejects empty body with 400", async () => {
    const res = await request(app).post("/api/analyze").send({});
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/repoUrl/i);
  });

  it("rejects malformed repoUrl with 400", async () => {
    const res = await request(app)
      .post("/api/analyze")
      .send({ repoUrl: "garbage" });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid/i);
  });
});

describe("Global error handler", () => {
  it("responds with 404 for unknown routes", async () => {
    const res = await request(app).get("/api/does-not-exist");
    expect(res.status).toBe(404);
  });
});
