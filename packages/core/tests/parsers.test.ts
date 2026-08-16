import { describe, it, expect } from "vitest";
import { GitHubClient } from "../src/github/client.js";
import { NpmParser } from "../src/parsers/npm-parser.js";
import { MavenParser } from "../src/parsers/maven-parser.js";
import { PythonParser } from "../src/parsers/python-parser.js";
import { getParserForFile } from "../src/parsers/index.js";

// ─── NPM Parser Tests ──────────────────────────────────────────────────────

describe("NpmParser", () => {
  const parser = new NpmParser();

  it("should parse dependencies and devDependencies", () => {
    const content = JSON.stringify({
      name: "test-project",
      version: "1.0.0",
      dependencies: {
        express: "^4.18.2",
        lodash: "~4.17.21",
      },
      devDependencies: {
        jest: ">=29.0.0",
        typescript: "5.3.0",
      },
    });

    const deps = parser.parse(content, "package.json");

    expect(deps).toHaveLength(4);

    // Check express
    const express = deps.find((d) => d.name === "express");
    expect(express).toBeDefined();
    expect(express!.version).toBe("4.18.2"); // ^ stripped
    expect(express!.isDev).toBe(false);
    expect(express!.ecosystem).toBe("npm");

    // Check jest
    const jest = deps.find((d) => d.name === "jest");
    expect(jest).toBeDefined();
    expect(jest!.version).toBe("29.0.0"); // >= stripped
    expect(jest!.isDev).toBe(true);

    // Check exact version
    const ts = deps.find((d) => d.name === "typescript");
    expect(ts!.version).toBe("5.3.0");
  });

  it("should handle empty dependencies", () => {
    const content = JSON.stringify({ name: "empty", version: "1.0.0" });
    const deps = parser.parse(content, "package.json");
    expect(deps).toHaveLength(0);
  });

  it("should handle malformed JSON gracefully", () => {
    const deps = parser.parse("not json at all", "package.json");
    expect(deps).toHaveLength(0);
  });
});

// ─── Maven Parser Tests ────────────────────────────────────────────────────

describe("MavenParser", () => {
  const parser = new MavenParser();

  it("should parse pom.xml dependencies", () => {
    const content = `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>test-app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
      <version>3.2.0</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>`;

    const deps = parser.parse(content, "pom.xml");

    expect(deps).toHaveLength(2);

    const spring = deps.find((d) =>
      d.name.includes("spring-boot-starter-web")
    );
    expect(spring).toBeDefined();
    expect(spring!.name).toBe(
      "org.springframework.boot:spring-boot-starter-web"
    );
    expect(spring!.version).toBe("3.2.0");
    expect(spring!.isDev).toBe(false);

    const junit = deps.find((d) => d.name.includes("junit"));
    expect(junit).toBeDefined();
    expect(junit!.isDev).toBe(true); // scope=test
  });

  it("should resolve property-based versions", () => {
    const content = `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <properties>
    <spring.version>3.2.0</spring.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>\${spring.version}</version>
    </dependency>
  </dependencies>
</project>`;

    const deps = parser.parse(content, "pom.xml");
    expect(deps).toHaveLength(1);
    expect(deps[0].version).toBe("3.2.0");
  });
});

// ─── Python Parser Tests ───────────────────────────────────────────────────

describe("PythonParser", () => {
  const parser = new PythonParser();

  it("should parse requirements.txt", () => {
    const content = `
flask==2.0.1
requests>=2.25.0
numpy~=1.21.0
# This is a comment
django

-r other-requirements.txt
`;

    const deps = parser.parse(content, "requirements.txt");

    expect(deps.length).toBeGreaterThanOrEqual(3);

    const flask = deps.find((d) => d.name === "flask");
    expect(flask).toBeDefined();
    expect(flask!.version).toBe("2.0.1");
    expect(flask!.ecosystem).toBe("pypi");

    const requests = deps.find((d) => d.name === "requests");
    expect(requests!.version).toBe("2.25.0");

    // django has no version
    const django = deps.find((d) => d.name === "django");
    expect(django).toBeDefined();
    expect(django!.version).toBe("latest");
  });

  it("should normalize PyPI package names", () => {
    const content = `Flask_RESTful==0.3.9\nPython_DateUtil==2.8.2`;
    const deps = parser.parse(content, "requirements.txt");

    expect(deps[0].name).toBe("flask-restful");
    expect(deps[1].name).toBe("python-dateutil");
  });

  it("should detect dev requirements", () => {
    const content = `pytest==7.0.0`;
    const deps = parser.parse(content, "requirements-dev.txt");
    expect(deps[0].isDev).toBe(true);
  });
});

// ─── Parser Registry Tests ─────────────────────────────────────────────────

describe("getParserForFile", () => {
  it("should return correct parser for each file type", () => {
    expect(getParserForFile("package.json")?.ecosystem).toBe("npm");
    expect(getParserForFile("pom.xml")?.ecosystem).toBe("maven");
    expect(getParserForFile("requirements.txt")?.ecosystem).toBe("pypi");
    expect(getParserForFile("unknown.file")).toBeNull();
  });
});

describe("GitHubClient", () => {
  it("should parse full GitHub HTTPS URLs and .git suffixes", () => {
    const client = new GitHubClient();

    expect(client.parseRepoUrl("https://github.com/xrishabh/VulnDetect.git")).toEqual({
      owner: "xrishabh",
      repo: "VulnDetect",
    });

    expect(client.parseRepoUrl("github.com/octocat/Hello-World")).toEqual({
      owner: "octocat",
      repo: "Hello-World",
    });
  });
});
