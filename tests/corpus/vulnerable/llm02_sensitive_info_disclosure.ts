/**
 * Customer lookup helper OpsBot uses to answer account questions.
 *
 * The whole customer record -- including SSN, date of birth, and full
 * billing address -- is serialized straight into the prompt so the model
 * has "enough context," with no field-level redaction and no minimization
 * to just what the question needs. Every one of those fields is now part
 * of what the model provider's logs retain, and part of what a
 * prompt-injected follow-up question could get the model to repeat back.
 */

import { generateText } from "ai";
import { createOpenAI } from "@ai-sdk/openai";

import { OPENAI_API_KEY, MODEL_NAME } from "./zt1_static_credentials";
import { customerDb } from "./customerDb";

const openaiProvider = createOpenAI({ apiKey: OPENAI_API_KEY });

interface CustomerRecord {
  fullName: string;
  ssn: string;
  dateOfBirth: string;
  billingAddress: string;
  cardLastFour: string;
}

export async function answerAccountQuestion(customerId: string, question: string): Promise<string> {
  const record: CustomerRecord = await customerDb.fetchCustomerRecord(customerId);
  const accountContext =
    `Customer: ${record.fullName}, SSN: ${record.ssn}, ` +
    `DOB: ${record.dateOfBirth}, Address: ${record.billingAddress}, ` +
    `Card on file: ${record.cardLastFour}`;

  const { text } = await generateText({
    model: openaiProvider(MODEL_NAME),
    system: "Answer the customer's question using their account context.",
    prompt: `${accountContext}\n\nQuestion: ${question}`,
    maxOutputTokens: 300,
  });
  return text;
}
