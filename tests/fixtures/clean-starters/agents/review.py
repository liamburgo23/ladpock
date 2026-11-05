import json
import anthropic

client = anthropic.Anthropic()


def review(text: str) -> dict:
    response = client.messages.create(model="claude-opus-5-5", max_tokens=1000, system="Review this text.", messages=[{"role": "user", "content": text}])
    result = response.content[0].text
    print("reviewed", len(result))
    return json.loads(result)
