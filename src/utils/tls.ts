// Self-signed TLS for the web panels. Real admin/camera UIs are almost always
// HTTPS, and scanners hit 443 — serving only plain HTTP is itself a tell. We
// generate a self-signed cert once and cache it to the runtime volume so the
// fingerprint is stable across restarts (regenerating every boot looks odd).
import fs from "fs/promises";
import path from "path";

const tlsDir = path.resolve("runtime", "tls");
const certPath = path.join(tlsDir, "cert.pem");
const keyPath = path.join(tlsDir, "key.pem");

export type TlsMaterial = { cert: string; key: string };

/** Load the cached cert, or generate + cache a new one. Null if generation fails. */
export async function getSelfSignedCert(commonName = "localhost"): Promise<TlsMaterial | null> {
  try {
    const [cert, key] = await Promise.all([fs.readFile(certPath, "utf8"), fs.readFile(keyPath, "utf8")]);
    if (cert && key) return { cert, key };
  } catch {
    /* not cached yet */
  }
  try {
    const selfsigned = (await import("selfsigned")).default as unknown as {
      generate: (attrs: Array<{ name: string; value: string }>, opts: Record<string, unknown>) => Promise<{ cert: string; private: string }>;
    };
    const pems = await selfsigned.generate([{ name: "commonName", value: commonName }], {
      days: 825,
      keySize: 2048,
      algorithm: "sha256",
    });
    await fs.mkdir(tlsDir, { recursive: true });
    await fs.writeFile(certPath, pems.cert, "utf8");
    await fs.writeFile(keyPath, pems.private, "utf8");
    return { cert: pems.cert, key: pems.private };
  } catch {
    return null;
  }
}
