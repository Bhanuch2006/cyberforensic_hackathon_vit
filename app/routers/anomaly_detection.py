"""
Anomaly Detection Router - Module 1
"""
from fastapi import APIRouter, HTTPException
from app.models.requests import AnomalyDetectionRequest
from app.models.responses import AnomalyDetectionResponse
from app.services.anomaly_detector import anomaly_detection_service

router = APIRouter(
    prefix="/api/v1",
    tags=["Anomaly Detection"]
)


@router.post("/detect-anomalies", response_model=AnomalyDetectionResponse)
async def detect_anomalies(request: AnomalyDetectionRequest):
    """
    Run anomaly detection on network traffic data
    
    **Module 1: Anomaly Detection**
    
    This endpoint performs inference using pre-trained ML models (no training).
    Uses ensemble of 7 algorithms: Autoencoder, IsolationForest, HBOS, 
    Statistical, COPOD, ECOD, and N-gram.
    
    **Input:**
    - input_file: Path to CSV file with network traffic data
    - threshold: Optional custom anomaly threshold (default: 0.5)
    
    **Output:**
    - forensiq_results_{timestamp}.csv: Full dataset with anomaly scores
    - anomalies_only_{timestamp}.csv: Only detected anomalies
    - metadata_{timestamp}.json: Detection statistics
    
    **Example:**
    ```json
    {
        "input_file": "data/UNSW_prepared.csv",
        "threshold": 0.5
    }
    ```
    """
    try:
        result = await anomaly_detection_service.detect_anomalies(
            input_file=request.input_file,
            threshold=request.threshold
        )
        
        return AnomalyDetectionResponse(
            status="success",
            message=f"Anomaly detection completed. Detected {result['statistics']['anomalies_detected']} anomalies.",
            output_files=result['output_files'],
            statistics=result['statistics']
        )
    
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=f"File not found: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Anomaly detection failed: {str(e)}")
