"""Création d'utilisateurs de test avec différents rôles (RBAC)."""
import asyncio
from sqlalchemy import select
from app.db.session import AsyncSessionLocal
from app.models.user import User, UserRole
from app.core.security import hash_password

TEST_USERS = [
    ("analyste", "Hajer Analyste", UserRole.ANALYST, "analyste123"),
    ("auditeur", "Haythem Auditeur",   UserRole.AUDITOR, "auditeur123"),
    ("lecteur",  "Feryel Lecteur",    UserRole.VIEWER,  "lecteur123"),
]

async def main():
    async with AsyncSessionLocal() as db:
        for username, full_name, role, password in TEST_USERS:
            result = await db.execute(select(User).where(User.username == username))
            if result.scalar_one_or_none():
                print(f"  Deja existant : {username}")
                continue
            user = User(
                email=f"{username}@securezone.com",
                username=username,
                full_name=full_name,
                hashed_password=hash_password(password),
                role=role,
                is_active=True,
                is_superuser=False,
            )
            db.add(user)
            print(f"  Cree : {username} / {password}  (role : {role.value})")
        await db.commit()
        print("\nTous les utilisateurs de test sont prets.")

if __name__ == "__main__":
    asyncio.run(main())