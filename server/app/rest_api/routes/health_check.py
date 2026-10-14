"""Health + readiness endpoints."""
from fastapi import APIRouter


router = APIRouter(tags=["health"])


@router.get("/health-check/")
def health_check():
    return {"status": "OK"}
