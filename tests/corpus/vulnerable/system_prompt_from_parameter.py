def chat(client, query):
    prompt = f"You must follow these instructions: {query}"
    return client.chat.completions.create(
        model="gpt-4o-mini",
        max_tokens=128,
        messages=[{"role": "system", "content": prompt}],
    )
