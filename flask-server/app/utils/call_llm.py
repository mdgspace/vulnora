import os
import json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()  

client = OpenAI(
    base_url="https://router.huggingface.co/v1",
    api_key=os.getenv("HF_TOKEN")
)

def call_llm(scan_results: dict):
    prompt = f"""
You are a security assistant. You will be given the results of a domain vulnerability scan.
Analyze them and generate exactly three paragraphs:
1) Explain the findings in simple, non-technical language so that a user with not much technical background can also easily understand it(what attacks were checked and what was found).
2) Describe the criticality/risk level of each issue (e.g. Low, Medium, High, Critical).
3) Provide recommended actions the user can take to fix or mitigate these issues.

Return the result as valid JSON with this format only:
{{
  "summary": "<paragraph explaining results>",
  "criticality": "<paragraph explaining risk levels>",
  "actions": "<paragraph explaining recommended actions>"
}}

Scan results:
{json.dumps(scan_results, indent=2)}

Important rules:
- Only return the JSON object, nothing else.
- No markdown, no explanations outside JSON.
- All fields must be non-empty text.
"""

    response = client.chat.completions.create(
        model="meta-llama/Llama-3.1-8B-Instruct:cerebras", 
        messages=[{"role": "user", "content": prompt}],
        max_tokens=500,
        temperature=0.4,
    )

    try:
        message = response.choices[0].message.content
        json_data = json.loads(message)
        return json_data
    except Exception as e:
        print("Failed to parse JSON:", e)
        print("Raw model output:", message)
        return None
