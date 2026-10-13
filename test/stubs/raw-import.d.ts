// Vite's `?raw` import suffix: the file's contents as a string. Used ONLY by the hub#93 twin-block pin
// in test/dispatch.test.ts, which hashes the Worker's own src/dispatch-params.ts block.
declare module "*?raw" {
  const source: string;
  export default source;
}
