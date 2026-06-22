from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.db.session import get_db
from app.models.asset import Asset
from app.schemas.asset import AssetCreate, AssetRead, AssetSummary, AssetUpdate
from app.api.deps import get_current_user, require_admin
from app.models.user import User

router = APIRouter(tags=["Assets"])


@router.get("/", response_model=List[AssetSummary])
async def list_assets(
    department: Optional[str] = Query(None),
    asset_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    query = select(Asset)
    if department:
        query = query.where(Asset.department == department)
    if asset_type:
        query = query.where(Asset.asset_type == asset_type)
    if status:
        query = query.where(Asset.status == status)
    if search:
        query = query.where(
            (Asset.hostname.ilike(f"%{search}%")) | (Asset.ip_address.ilike(f"%{search}%"))
        )
    query = query.offset(skip).limit(limit).order_by(Asset.risk_score.desc())
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/stats")
async def asset_stats(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    total = await db.scalar(select(func.count(Asset.id)))
    online = await db.scalar(select(func.count(Asset.id)).where(Asset.status == "online"))
    avg_compliance = await db.scalar(select(func.avg(Asset.compliance_score)))
    avg_risk = await db.scalar(select(func.avg(Asset.risk_score)))
    return {
        "total": total or 0,
        "online": online or 0,
        "offline": (total or 0) - (online or 0),
        "avg_compliance_score": round(avg_compliance or 0, 1),
        "avg_risk_score": round(avg_risk or 0, 1),
    }


@router.get("/{asset_id}", response_model=AssetRead)
async def get_asset(
    asset_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset introuvable")
    return asset


@router.post("/", response_model=AssetRead)
async def create_asset(
    payload: AssetCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
):
    existing = await db.execute(select(Asset).where(Asset.ip_address == payload.ip_address))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Un asset avec cette IP existe déjà")
    asset = Asset(**payload.model_dump())
    db.add(asset)
    await db.flush()
    await db.refresh(asset)
    return asset


@router.patch("/{asset_id}", response_model=AssetRead)
async def update_asset(
    asset_id: int,
    payload: AssetUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset introuvable")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(asset, field, value)
    await db.flush()
    await db.refresh(asset)
    return asset


@router.delete("/{asset_id}", dependencies=[Depends(require_admin)])
async def delete_asset(asset_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset introuvable")
    await db.delete(asset)
    return {"message": "Asset supprimé"}
