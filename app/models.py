import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional
from urllib.parse import urlparse

@dataclass
class ParsedEmail:
    message_id: str
    api_key_id: str
    sender: str
    recipient: str
    subject: str
    html_body: str = ""
    text_body: str = ""
    reply_to: Optional[str] = None
    attachments: List[str] = field(default_factory=list)
    sent_at: datetime = field(default_factory=datetime.utcnow)
    
    @property
    def sender_domain(self) -> str:
        return self.sender.split("@")[-1] if "@" in self.sender else self.sender

    @property
    def full_text(self) -> str:
        stripped_html = re.sub(r'<[^>]+>', ' ', self.html_body)
        return f"{self.subject}\n{self.text_body}\n{stripped_html}"

    @property
    def links(self) -> List[str]:
        hrefs = re.findall(r'href=["\']([^"\']+)["\']', self.html_body, re.IGNORECASE)
        plain = re.findall(r'https?://[^\s"\'<>]+', self.text_body)
        return list(dict.fromkeys(hrefs + plain))

    @property
    def link_domains(self) -> List[str]:
        domains = []
        for link in self.links:
            netloc = urlparse(link).netloc
            if netloc:
                domains.append(netloc.split(":")[0])
        return domains