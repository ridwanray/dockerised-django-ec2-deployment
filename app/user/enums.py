from dataclasses import dataclass

TOKEN_TYPE_CHOICE = (
    ("ACCOUNT_VERIFICATION", "ACCOUNT_VERIFICATION"),
    ("PASSWORD_RESET", "PASSWORD_RESET"),
)

ROLE_CHOICE = (
    ("HIRER", "HIRER"),
    ("TALENT", "TALENT"),
    ("ADMIN", "ADMIN"),
)

@dataclass
class TokenEnum:
    ACCOUNT_VERIFICATION = "ACCOUNT_VERIFICATION"
    PASSWORD_RESET = "PASSWORD_RESET"


@dataclass
class SystemRoleEnum:
    REGULAR = "REGULAR"
    SuperAdmin = "SuperAdmin"
    ADMIN = "ADMIN"
