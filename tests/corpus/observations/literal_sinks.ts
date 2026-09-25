import { execSync } from "node:child_process";

const response = "printf hello";
execSync(response);

const expression = "1 + 1";
export const result = eval(expression);

export function messages(query: string) {
  const prompt = `Summarize this text: ${query}`;
  return [
    { role: "system", content: "Summarize the user text." },
    { role: "user", content: prompt },
  ];
}
