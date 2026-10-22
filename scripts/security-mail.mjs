import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:https";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const require = createRequire(new URL("../packages/features/auth/package.json", import.meta.url));
const mail = require("nodemailer");
const fetchMail = require("nodemailer/lib/fetch");

test("renders mail locally without SMTP delivery", async () => {
  const transport = mail.createTransport({ streamTransport: true, buffer: true, newline: "unix" });
  const result = await transport.sendMail({
    from: "sender@example.test",
    to: "receiver@example.test",
    subject: "Security regression",
    text: "Local fixture only",
  });
  assert.ok(Buffer.isBuffer(result.message));
  assert.match(result.message.toString(), /Subject: Security regression/);
  assert.match(result.message.toString(), /Local fixture only/);
  transport.close();
});

test("accepts SMTP URL configuration", () => {
  const transport = mail.createTransport("smtps://localhost:465");
  assert.equal(transport.transporter.options.host, "localhost");
  assert.equal(transport.transporter.options.secure, true);
  transport.close();
});

test("internal HTTPS fetch rejects an untrusted certificate", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mail-tls-regression-"));
  let server;
  let requests = 0;
  try {
    execFileSync(
      "openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=localhost",
        "-keyout",
        join(dir, "key.pem"),
        "-out",
        join(dir, "cert.pem"),
      ],
      { stdio: "ignore" }
    );
    server = createServer(
      { key: readFileSync(join(dir, "key.pem")), cert: readFileSync(join(dir, "cert.pem")) },
      (_req, res) => {
        requests++;
        res.end("fixture");
      }
    );
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    await assert.rejects(
      new Promise((resolve, reject) => {
        const stream = fetchMail(`https://127.0.0.1:${server.address().port}/`);
        stream.on("error", reject);
        stream.on("end", resolve);
        stream.resume();
      }),
      /certificate|self.signed|unable to verify/i
    );
    assert.equal(requests, 0);
  } finally {
    if (server) await new Promise((resolve) => server.close(resolve));
    rmSync(dir, { recursive: true, force: true });
  }
});
