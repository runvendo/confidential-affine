// Browser stub for Node's "zlib". The verifier only reaches its zlib fallback
// when DecompressionStream is unavailable; every supported browser provides
// DecompressionStream, so this path is dead in the bundle. The stub exists so
// esbuild can resolve the dynamic import without pulling in a Node polyfill.
export function gunzipSync() {
  throw new Error("zlib unavailable in browser; DecompressionStream should be used");
}
