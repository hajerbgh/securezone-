from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.db.session import get_db
from app.models.alert import Alert, AlertStatus, AlertSeverity
from app.schemas.alert import AlertRead, AlertUpdate, AlertStats
from app.api.deps import get_current_user, require_analyst
from app.models.user import User

router = APIRouter(tags=["Alertes"])


@router.get("/", response_model=List[AlertRead])
async def list_alerts(
    severity: Optional[AlertSeverity] = Query(None),
    status: Optional[AlertStatus] = Query(None),
    category: Optional[str] = Query(None),
    asset_id: Optional[int] = Query(None),
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    query = select(Alert)
    if severity:
        query = query.where(Alert.severity == severity)
    if status:
        query = query.where(Alert.status == status)
    if category:
        query = query.where(Alert.category == category)
    if asset_id:
        query = query.where(Alert.asset_id == asset_id)
    query = query.offset(skip).limit(limit).order_by(Alert.created_at.desc())
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/stats", response_model=AlertStats)
async def alert_stats(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    total = await db.scalar(select(func.count(Alert.id)))
    open_count = await db.scalar(select(func.count(Alert.id)).where(Alert.status == AlertStatus.OPEN))

    by_severity = {}
    for sev in ["critical", "high", "medium", "low"]:
        count = await db.scalar(select(func.count(Alert.id)).where(Alert.severity == sev))
        by_severity[sev] = count or 0

    by_cat_result = await db.execute(
        select(Alert.category, func.count(Alert.id).label("n"))
        .group_by(Alert.category)
        .order_by(func.count(Alert.id).desc())
    )
    by_category = {str(row[0].value if hasattr(row[0], "value") else row[0]): row[1]
                   for row in by_cat_result}

    by_status_result = await db.execute(
        select(Alert.status, func.count(Alert.id).label("n"))
        .group_by(Alert.status)
    )
    by_status = {str(row[0].value if hasattr(row[0], "value") else row[0]): row[1]
                 for row in by_status_result}

    return AlertStats(
        total=total or 0,
        open=open_count or 0,
        critical=by_severity["critical"],
        high=by_severity["high"],
        medium=by_severity["medium"],
        low=by_severity["low"],
        by_category=by_category,
        by_status=by_status,
    )


@router.get("/{alert_id}", response_model=AlertRead)
async def get_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alerte introuvable")
    return alert


@router.patch("/{alert_id}", response_model=AlertRead)
async def update_alert(
    alert_id: int,
    payload: AlertUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alerte introuvable")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(alert, field, value)

    if payload.status == AlertStatus.RESOLVED:
        from datetime import datetime, timezone
        alert.resolved_by_id = current_user.id
        alert.resolved_at = datetime.now(timezone.utc)

    await db.flush()
    await db.refresh(alert)
    return alert
