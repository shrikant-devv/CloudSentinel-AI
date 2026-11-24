
import boto3
import json

AWS_REGION = "ap-southeast-2"
MODEL_ID = "amazon.nova-lite-v1:0"

bedrock_client = boto3.client(
    service_name="bedrock-runtime",
    region_name=AWS_REGION
)


def analyze_security_event(event: dict) -> dict:
    prompt = f"""
You are CloudSentinel AI, a cloud security threat analyst.

Analyze the following security event.

Security event:
{json.dumps(event, indent=2)}

Return a JSON object with these fields:
- threat
- risk_level (Low, Medium, or High)
- reason
- recommendations (array of strings)
- response_steps (array of strings)

Only classify the event and recommend defensive actions.
Do not claim that you performed any AWS security actions.
Return valid JSON only.
"""

    response = bedrock_client.converse(
        modelId=MODEL_ID,
        messages=[
            {
                "role": "user",
                "content": [{"text": prompt}]
            }
        ],
        inferenceConfig={
            "maxTokens": 700,
            "temperature": 0.2
        }
    )

    result = response["output"]["message"]["content"][0]["text"]

    # Extract JSON response
    result = result.strip()

    if result.startswith("```"):
        result = result.removeprefix("```json").removeprefix("```")
        result = result.removesuffix("```").strip()

    return json.loads(result)
