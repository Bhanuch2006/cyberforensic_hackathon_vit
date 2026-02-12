"""
Correlation Engine Router - Module 2
"""
from fastapi import APIRouter, HTTPException
from app.models.requests import CorrelationRequest
from app.models.responses import CorrelationResponse
from app.services.correlation_engine import correlation_engine

router = APIRouter(
    prefix="/api/v1",
    tags=["Correlation"]
)


@router.post("/correlate-attacks", response_model=CorrelationResponse)
async def correlate_attacks(request: CorrelationRequest):
    """
    Build attack chains from anomaly detection results
    
    **Module 2: Hybrid Correlation Engine**
    
    Performs context-aware attack chain detection using:
    - Full dataset for baseline establishment
    - Anomalies as trigger points
    - N-gram pattern analysis
    - Baseline deviation detection
    - Gradual escalation detection
    
    **Input:**
    - full_results_file: forensiq_results_{timestamp}.csv from Module 1
    - anomalies_file: anomalies_only_{timestamp}.csv from Module 1
    
    **Output:**
    - hybrid_attack_chains_{timestamp}.json: Complete attack chains
    - hybrid_chain_summary_{timestamp}.csv: Tabular summary
    - hybrid_correlation_stats_{timestamp}.json: Statistics
    
    **Example:**
    ```json
    {
        "full_results_file": "output/forensiq_results_20260203_101432.csv",
        "anomalies_file": "output/anomalies_only_20260203_101432.csv"
    }
    ```
    """
    try:
        result = await correlation_engine.correlate(
            full_results_file=request.full_results_file,
            anomaly_file=request.anomalies_file
        )
        
        return CorrelationResponse(
            status="success",
            message=f"Correlation completed. Created {result['statistics']['total_chains']} attack chains.",
            output_files=result['output_files'],
            statistics=result['statistics']
        )
    
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=f"File not found: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Correlation failed: {str(e)}")
