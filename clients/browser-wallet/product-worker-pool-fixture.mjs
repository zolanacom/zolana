// Public NPOOL004 header/length fixture for inert worker-core tests, not valid
// consensus state or a replacement for the Rust pool decoder.
export function hintAccount() {
  const bytes=Buffer.alloc(25728);bytes.write("NPOOL004");bytes.fill(7,8,40);
  return {owner:"1".repeat(32),data:[bytes.toString("base64"),"base64"]};
}
