// Single source of truth for the TID-Recon-Dog banner.
// Printed first on startup (before ports open) and served to the web GUI, where
// it glows briefly on load before the metrics render.

export const ASCII_LOGO = String.raw`
      ______     __     __     ______
     /\  == \   /\ \   /\ \   /\  ___\
     \ \  __<   \ \ \  \ \ \  \ \  __\
      \ \_\ \_\  \ \_\  \ \_\  \ \_____\
       \/_/ /_/   \/_/   \/_/   \/_____/

T   54    A   41    N   4E    G   47    O   4F    I   49    S   53    D   44    O   4F    W   57    N   4E    -   2D
R   52    E   45    C   43    O   4F    N   4E    -   2D
D   44    O   4F    G   47

            BRAVE NEW WORLD . .  .  .


           𓏺𓏺 𓎆𓎆𓏺𓏺𓏺𓏺𓏺𓏺 𓆼𓆼 𓎆𓎆 𓏺𓏺𓏺𓏺𓏺






  -'ALL WARFARE IS BASED ON DECEPTION'-

  - - -  -  - --SUN TZU'--- - -- - - -  -
`;

/** Print the banner to the terminal (burgundy) before services start. */
export function printLogo() {
  const burgundy = "\x1b[38;5;131m";
  const reset = "\x1b[0m";
  console.log(burgundy + ASCII_LOGO + reset);
}
