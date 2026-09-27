// fork: the opencyber wordmark replaces upstream's "code" block with "cyber" (F-011), drawn in the
// same 4 wide x 5 tall blocky glyphs. `component/logo.tsx` renders `right` in text.brand.base, so
// "cyber" takes the theme's red while `left` stays the muted "open" of the upstream wordmark.
export const logo = {
  left: ["                   ", "█▀▀█ █▀▀█ █▀▀█ █▀▀▄", "█__█ █__█ █^^^ █__█", "▀▀▀▀ █▀▀▀ ▀▀▀▀ ▀~~▀"],
  right: [
    "          ▄             ",
    "█▀▀▀ █  █ █▀▀█ █▀▀█ █▀▀█",
    "█___  ██  █__█ █^^^ █   ",
    "▀▀▀▀  █   ▀▀▀▀ ▀▀▀▀ ▀   ",
  ],
}
