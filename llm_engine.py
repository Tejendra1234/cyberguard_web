import requests

OLLAMA_URL = "http://10.70.28.207:11434/api/generate"

def explain_with_llm(module_name, module_output):

    prompt = f"""
You are a professional SOC cybersecurity analyst.

Explain the tool result below in simple language.

MODULE:
{module_name}

RESULT:
{module_output}

Provide:

1. What the result means
2. Security implications
3. Possible attacks
4. Recommended mitigation
5. Real-world example

Answer in Markdown.
"""

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": "llama3",
                "prompt": prompt,
                "stream": False
            },
            timeout=120
        )

        data = response.json()

        return data.get("response", "AI explanation not available.")

    except Exception as e:
        return f"LLM connection error: {str(e)}"