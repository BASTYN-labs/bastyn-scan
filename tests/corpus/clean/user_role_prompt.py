def chat(client, query):
    prompt = f"Summarize this text: {query}"
    return client.chat.completions.create(
        model="gpt-4o-mini",
        max_tokens=128,
        messages=[
            {"role": "system", "content": "Summarize the user text."},
            {"role": "user", "content": prompt},
        ],
    )


def greeting():
    user_name = "Alice"
    system_prompt = f"You assist {user_name}."
    return system_prompt
