"""Customer lookup helper OpsBot uses to answer account questions.

known_gap (LLM02): no rule in bastyn.yml inspects what data is packed into
a message sent to the model. A hardcoded-secret rule (BAS-ZT1-001) and a
prompt-template-secret rule (BAS-LLM08-001) exist, but neither one looks at
a runtime f-string built from a database row and handed to the chat API,
which is exactly the shape a real PII leak takes.
"""

from openai import OpenAI

from zt1_static_credentials import OPENAI_API_KEY, MODEL_NAME
from customer_db import fetch_customer_record

client = OpenAI(api_key=OPENAI_API_KEY)


def answer_account_question(customer_id: str, question: str) -> str:
    """Answer a customer's question using their full account record.

    The whole customer record -- including SSN, date of birth, and full
    billing address -- is serialized straight into the prompt so the model
    has "enough context", with no field-level redaction and no minimization
    to just what the question needs. Every one of those fields is now part
    of what the model provider's logs retain, and part of what a
    prompt-injected follow-up question could get the model to repeat back.
    """
    record = fetch_customer_record(customer_id)
    context = (
        f"Customer: {record.full_name}, SSN: {record.ssn}, "
        f"DOB: {record.date_of_birth}, Address: {record.billing_address}, "
        f"Card on file: {record.card_last_four}"
    )
    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": "Answer the customer's question using their account context."},
            {"role": "user", "content": f"{context}\n\nQuestion: {question}"},
        ],
        max_tokens=300,
    )
    return response.choices[0].message.content
