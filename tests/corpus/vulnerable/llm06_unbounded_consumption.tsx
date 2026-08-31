/**
 * Ticket-digest panel for OpsBot's on-call dashboard.
 *
 * A Next.js App Router Server Component: it summarizes a batch of ticket
 * text server-side and renders the result directly, no client-side
 * fetch involved.
 */

import { streamText } from "ai";
import { createOpenAI } from "@ai-sdk/openai";

import { OPENAI_API_KEY, MODEL_NAME } from "./zt1_static_credentials";

const openaiProvider = createOpenAI({ apiKey: OPENAI_API_KEY });

/**
 * Summarize an arbitrarily long batch of ticket text for the digest.
 *
 * No maxOutputTokens is set, so nothing here bounds a single call's cost
 * or latency. A caller could pass in a whole day's worth of tickets and
 * the response length is unbounded too. This is an observation, not a
 * defect -- a gateway limiter elsewhere in the deployment might already
 * cap it, and the source alone cannot say.
 */
async function summarizeTicketBacklog(ticketText: string) {
  const result = streamText({
    model: openaiProvider(MODEL_NAME),
    system: "Summarize the following support tickets.",
    prompt: ticketText,
  });
  return result;
}

export default async function TicketDigestPanel({ ticketText }: { ticketText: string }) {
  const summary = await summarizeTicketBacklog(ticketText);
  const text = await summary.text;
  return (
    <section>
      <h2>Daily ticket digest</h2>
      <p>{text}</p>
    </section>
  );
}
