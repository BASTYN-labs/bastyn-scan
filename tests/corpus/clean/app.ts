/**
 * HTTP surface for OpsBot's Node service (safe).
 */

import express from "express";

import { askModel } from "./agent";

const app = express();
app.use(express.json());

/**
 * Public, unauthenticated endpoint.
 *
 * Correct for a public chatbot with nothing sensitive behind it. There is
 * also no rate limiting anywhere in this file: unprovable from the
 * repository, since the limiter normally lives at the edge (a proxy or
 * gateway).
 */
app.post("/chat", async (req, res) => {
  const incidentSummary = req.body?.message ?? "";
  const reply = await askModel(incidentSummary);
  res.json({ reply });
});

export default app;
