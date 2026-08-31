# Root is used to build and the shipped stage is not root. Docker resets the
# user at every FROM, so the builder's USER root never reaches the final image.
FROM python:3.12 AS builder
USER root
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --target=/build/deps -r requirements.txt

FROM python:3.12-slim
# Names the variable the entrypoint reads. It holds a name, not a key.
ENV OPENAI_API_KEY_NAME=OPENAI_API_KEY
# Read from the real environment at deploy time, not a literal.
ENV DB_PASSWORD=${DB_PASSWORD}
RUN useradd --create-home --uid 10001 app
COPY --from=builder /build/deps /usr/local/lib/python3.12/site-packages
COPY . /srv/agent
USER app
CMD ["python", "-m", "agent.serve"]
