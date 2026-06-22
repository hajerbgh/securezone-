"""Script de création de l'utilisateur admin SecureZone."""
import asyncio
from sqlalchemy import select
from app.db.session import AsyncSessionLocal
from app.models.user import User, UserRole
from app.core.security import hash_password


async def main():
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == "admin"))
        existing = result.scalar_one_or_none()

        if existing:
            existing.hashed_password = hash_password("admin123")
            existing.is_active = True
            await db.commit()
            print("Mot de passe admin reinitialise -> admin / admin123")
        else:
            admin = User(
                email="admin@securezone.local",
                username="admin",
                full_name="Admin SecureZone",
                hashed_password=hash_password("admin123"),
                role=UserRole.ADMIN,
                is_active=True,
                is_superuser=True,
            )
            db.add(admin)
            await db.commit()
            print("Compte admin cree -> admin / admin123")


if __name__ == "__main__":
    asyncio.run(main())