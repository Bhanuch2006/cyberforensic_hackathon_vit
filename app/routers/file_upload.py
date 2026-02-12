"""
File Upload Router - Handles CSV upload and processing
"""
from fastapi import APIRouter, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse
import pandas as pd
from io import BytesIO
from pathlib import Path
from datetime import datetime
from app.core.config import settings
from app.services import (
    anomaly_detector,
    correlation_engine,
    ip_enricher,
    mitre_mapper,
    story_generator
)

router = APIRouter(
    prefix="/api/v1",
    tags=["File Upload"]
)


@router.post("/upload-csv")
async def upload_csv(file: UploadFile = File(...)):
    """
    Upload CSV file and run full ForensIQ pipeline
    
    **Process:**
    1. Receive and validate CSV file
    2. Save to data directory
    3. Run full detection pipeline
    4. Return results for dashboard visualization
    
    **Returns:**
    - Upload metadata
    - Anomaly detection summary
    - Attack chains detected
    - Top IOCs (IPs, patterns)
    - Sample data rows
    """
    try:
        # Validate file type
        if not file.filename.endswith('.csv'):
            raise HTTPException(
                status_code=400,
                detail="Invalid file type. Please upload a CSV file."
            )
        
        # Read uploaded file
        contents = await file.read()
        
        # Load into pandas DataFrame
        try:
            df = pd.read_csv(BytesIO(contents))
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to parse CSV: {str(e)}"
            )
        
        # Validate CSV is not empty
        if df.empty:
            raise HTTPException(
                status_code=400,
                detail="CSV file is empty"
            )
        
        # Save uploaded file to data directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        uploaded_filename = f"uploaded_{timestamp}.csv"
        upload_path = Path("data") / uploaded_filename
        
        # Ensure data directory exists
        Path("data").mkdir(exist_ok=True)
        
        # Save file
        df.to_csv(upload_path, index=False)
        
        # ==================================================
        # RUN FULL FORENSIQ PIPELINE
        # ==================================================
        
        print(f"\n🔍 Processing {file.filename} ({len(df)} records)...")
        
        # Step 1: Anomaly Detection
        print("   [1/5] Running anomaly detection...")
        anomaly_results = anomaly_detector.detect(str(upload_path))
        anomaly_df = pd.read_csv(anomaly_results['output_file'])
        
        # Step 2: Correlation Engine
        print("   [2/5] Building attack chains...")
        correlation_results = correlation_engine.correlate(anomaly_results['output_file'])
        
        # Step 3: IP Enrichment
        print("   [3/5] Enriching IP addresses...")
        enrichment_results = ip_enricher.enrich(correlation_results['output_file'])
        
        # Step 4: MITRE ATT&CK Mapping
        print("   [4/5] Mapping MITRE techniques...")
        mitre_results = mitre_mapper.map_attacks(enrichment_results['output_file'])
        
        # Step 5: Story Generation
        print("   [5/5] Generating attack narratives...")
        story_results = story_generator.generate(mitre_results['output_file'])
        
        print("   ✅ Pipeline complete!\n")
        
        # ==================================================
        # PREPARE DASHBOARD RESPONSE
        # ==================================================
        
        # Summary statistics
        total_records = len(anomaly_df)
        anomaly_count = int(anomaly_df['is_anomaly'].sum())
        threat_rate = round((anomaly_count / total_records) * 100, 2)
        
        # Extract attack chains from correlation results
        attack_chains = []
        if 'attack_chains' in correlation_results:
            for chain_id, chain_data in correlation_results['attack_chains'].items():
                attack_chains.append({
                    "id": chain_id,
                    "severity": _get_severity(chain_data['score']),
                    "pattern": chain_data.get('pattern', 'Unknown'),
                    "count": chain_data['event_count'],
                    "score": round(chain_data['score'], 2)
                })
        
        # Extract top malicious IPs
        malicious_ips = []
        if 'srcip' in anomaly_df.columns:
            top_ips = (
                anomaly_df[anomaly_df['is_anomaly'] == 1]
                .groupby('srcip')
                .size()
                .sort_values(ascending=False)
                .head(5)
            )
            malicious_ips = [
                {"ip": ip, "count": int(count)} 
                for ip, count in top_ips.items()
            ]
        
        # Extract MITRE techniques
        mitre_techniques = []
        if 'mitre_techniques' in mitre_results:
            for technique in mitre_results['mitre_techniques'][:10]:
                mitre_techniques.append({
                    "id": technique['technique_id'],
                    "name": technique['name'],
                    "tactic": technique['tactic'],
                    "count": technique.get('count', 1)
                })
        
        # Get attack narratives
        attack_stories = []
        if 'stories' in story_results:
            attack_stories = story_results['stories'][:3]  # Top 3 stories
        
        # Prepare sample data rows
        sample_rows = anomaly_df.head(100).to_dict(orient='records')
        
        # Build response
        response = {
            "status": "success",
            "upload_info": {
                "original_name": file.filename,
                "saved_name": uploaded_filename,
                "size": len(contents),
                "records": total_records,
                "timestamp": timestamp
            },
            "summary": {
                "total": total_records,
                "anomalies": anomaly_count,
                "rate": threat_rate,
                "chains_detected": len(attack_chains)
            },
            "attack_chains": attack_chains,
            "malicious_ips": malicious_ips,
            "mitre_techniques": mitre_techniques,
            "attack_stories": attack_stories,
            "rows": sample_rows,
            "pipeline_outputs": {
                "anomaly_file": anomaly_results['output_file'],
                "correlation_file": correlation_results['output_file'],
                "enrichment_file": enrichment_results['output_file'],
                "mitre_file": mitre_results['output_file'],
                "story_file": story_results['output_file']
            }
        }
        
        return JSONResponse(content=response)
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error processing file: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Processing failed: {str(e)}"
        )


def _get_severity(score: float) -> str:
    """Map correlation score to severity level"""
    if score >= 0.8:
        return "CRITICAL"
    elif score >= 0.6:
        return "HIGH"
    elif score >= 0.4:
        return "MEDIUM"
    else:
        return "LOW"
