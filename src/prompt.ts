import { createInterface } from "node:readline";

export const maskedInput = (prompt: string) => {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise<string>((resolve) => {
    let masked = true;

    rl.question(prompt, (value) => {
      resolve(value);
      rl.close();
      masked = false;
    });

    (rl as any)._writeToOutput = function _writeToOutput(buffer: string) {
      if (masked && buffer !== "\r\n") {
        (rl as any).output.write("*");
      } else (rl as any).output.write(buffer);
    };
  });
};
