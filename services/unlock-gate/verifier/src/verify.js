// In-browser attestation verify-gate for the confidential-affine unlock page.
//
// Bundled (esbuild, IIFE) into dist/verifier.bundle.js and embedded into the Go
// gate binary, then self-served from the enclave at /__verifier.js. It MUST be
// served from inside the attested enclave (never a CDN) so the verifier code
// itself is covered by the measurement it checks.
//
// Exposes window.TinfoilVerify(enclaveDomain, configRepo): runs Tinfoil's
// browser-native attestation verification (sigstore-browser + tuf-browser +
// WebCrypto, no trusted remote verifier) and resolves to a plain result the
// inline page can branch on.
import { Verifier } from "tinfoil";

// enclaveDomain is a bare host (e.g. location.host); the Verifier wants an https URL.
function toServerURL(enclaveDomain) {
  if (/^https?:\/\//i.test(enclaveDomain)) return enclaveDomain;
  return "https://" + enclaveDomain;
}

window.TinfoilVerify = async function TinfoilVerify(enclaveDomain, configRepo) {
  try {
    const verifier = new Verifier({
      serverURL: toServerURL(enclaveDomain),
      configRepo: configRepo,
    });
    await verifier.verify();
    const doc = verifier.getVerificationDocument();
    return { ok: doc != null && doc.securityVerified === true, doc };
  } catch (err) {
    return {
      ok: false,
      error: (err && (err.message || String(err))) || "verification failed",
    };
  }
};
