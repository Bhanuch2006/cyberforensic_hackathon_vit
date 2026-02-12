"""
IP Enrichment Router - Module 3
"""
from fastapi import APIRouter, HTTPException
from app.models.requests import EnrichmentRequest
from app.models.responses import EnrichmentResponse
from app.services.ip_enricher import ip_enrichment_service

router = APIRouter(
    prefix="/api/v1",
    tags=["IP Enrichment"]
)


@router.post("/enrich-ips", response_model=EnrichmentResponse)
async def enrich_ips(request: EnrichmentRequest):
    """
    Enrich attack chains with IP reputation data
    
    **Module 3: IP Reputation Enrichment**
    
    Enriches attack chains with ground truth IP reputation from UNSW dataset
    labels combined with behavior-based scoring.
    
    Scoring method:
    - 70% Ground truth (from dataset labels)
    - 30% Behavior analysis (attack severity, patterns, deviations)
    
    **Input:**
    - chains_file: hybrid_attack_chains_{timestamp}.json from Module 2
    - dataset_file: UNSW_prepared.csv (for ground truth labels)
    
    **Output:**
    - enriched_chains_{timestamp}_ground_truth.json: Chains with IP reputation
    
    **Example:**
    ```json
    {
        "chains_file": "output/hybrid_attack_chains_20260203_101432.json",
        "dataset_file": "data/UNSW_prepared.csv"
    }
    ```
    """
    try:
        result = await ip_enrichment_service.enrich_chains(
            chains_file=request.chains_file,
            dataset_file=request.dataset_file
        )
        
        return EnrichmentResponse(
            status="success",
            message=f"IP enrichment completed. Enriched {result['statistics']['total_chains']} chains.",
            output_file=result['output_files']['enriched_chains'],
            statistics=result['statistics']
        )
    
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=f"File not found: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"IP enrichment failed: {str(e)}")
