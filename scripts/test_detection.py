import json
from pathlib import Path
from app.schemas import EmailInput, AttachmentMeta
from app.detection.engine import run_detection


def run_sample(path: str):
    data = json.loads(Path(path).read_text())
    email = EmailInput(
        subject=data.get("subject", ""),
        body_text=data.get("body_text"),
        body_html=data.get("body_html"),
        sender_email=data.get("sender_email", ""),
        sender_display_name=data.get("sender_display_name"),
        attachments=[AttachmentMeta(**a) for a in data.get("attachments", [])],
    )
    result = run_detection(email)
    print(f"\n=== {Path(path).name} ===")
    print(result.model_dump_json(indent=2))


if __name__ == "__main__":
    for p in [
        "/workspace/samples/phish_invoice.json",
        "/workspace/samples/benign_newsletter.json",
    ]:
        run_sample(p)
