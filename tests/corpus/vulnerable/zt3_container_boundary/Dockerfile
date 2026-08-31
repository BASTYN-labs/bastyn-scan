# The deployment image for the runbook agent.
FROM python:3.12-slim

WORKDIR /srv/agent
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# Baked into an image layer, so `docker inspect` reads it straight back out.
ENV OPENAI_API_KEY=sk-proj-9f2b7d41c6a8e35019bdae74

# A weak, hardcoded database password baked into the image the same way --
# not a provider key, so BAS-INFRA-002's `sk-`-shaped gate doesn't cover it.
ENV DB_PASSWORD=Sup3rWeakPass!

# Root was taken to install packages and never given back before the
# entrypoint runs, so the agent and every tool it spawns run as root.
USER root
CMD ["python", "-m", "agent.serve"]
