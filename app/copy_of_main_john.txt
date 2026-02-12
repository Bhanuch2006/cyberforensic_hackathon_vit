from fastapi import FastAPI, Request, File, UploadFile, Form
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

import os
import shutil
import traceback
from pathlib import Path


app = FastAPI(
    title="ForensIQ API",
    description="Cybersecurity Threat Detection Platform",
    version="1.0.0"
)


# Get the project root directory (parent of app/)
BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
UPLOAD_DIR = BASE_DIR / "data" / "uploads"


# Create directories if they don't exist
STATIC_DIR.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Setup templates (pointing to root-level templates folder)
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


# Mount static files
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# Serve frontend at root URL
@app.get("/", response_class=HTMLResponse)
async def serve_frontend(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


# Health check
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "models_loaded": True,
        "data_available": True,
        "config": {
            "version": "1.0.0"
        }
    }


# Main pipeline endpoint with file upload
@app.post("/api/v1/run-full-pipeline")
async def run_full_pipeline(
    file: UploadFile = File(...),
    threshold: float = Form(0.5)
):
    """Run the full ForensIQ detection pipeline with uploaded CSV file"""
    
    try:
        print("="*50)
        print(f"Received file upload request")
        print(f"Filename: {file.filename}")
        print(f"Content Type: {file.content_type}")
        print(f"Threshold: {threshold}")
        print("="*50)
        
        # Validate file is CSV
        if not file.filename.endswith('.csv'):
            return JSONResponse(
                status_code=400,
                content={
                    "status": "error",
                    "message": "Only CSV files are accepted"
                }
            )
        
        # Save uploaded file
        file_path = UPLOAD_DIR / file.filename
        
        with file_path.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        print(f"✓ File saved to: {file_path}")
        
        # Now run your pipeline with the uploaded file
        input_file = str(file_path)
        
        # ================================================
        # TODO: Replace this with your actual pipeline code
        # ================================================
        # Example:
        # from app.modules.module_1_anomaly_detection import detect_anomalies
        # from app.modules.module_2_correlation import correlate_attacks
        # from app.modules.module_3_enrichment import enrich_ips
        # from app.modules.module_4_mitre_mapping import map_mitre
        # from app.modules.module_5_story_generation import generate_stories
        
        # import time
        # start_time = time.time()
        
        # Module 1: Anomaly Detection
        # print("Running Module 1: Anomaly Detection...")
        # anomaly_results = detect_anomalies(input_file, threshold)
        
        # Module 2: Correlation
        # print("Running Module 2: Correlation Engine...")
        # correlation_results = correlate_attacks(
        #     anomaly_results['forensiq_results'],
        #     anomaly_results['anomalies_only']
        # )
        
        # Module 3: IP Enrichment
        # print("Running Module 3: IP Enrichment...")
        # enrichment_results = enrich_ips(
        #     correlation_results['attack_chains'],
        #     input_file
        # )
        
        # Module 4: MITRE Mapping
        # print("Running Module 4: MITRE ATT&CK Mapping...")
        # mitre_results = map_mitre(enrichment_results['enriched_chains'])
        
        # Module 5: Story Generation
        # print("Running Module 5: Story Generation...")
        # story_results = generate_stories(mitre_results['mitre_chains'])
        
        # total_time = time.time() - start_time
        # ================================================
        
        # TEMPORARY: Mock response for testing
        # Remove this when you integrate your actual modules
        response = {
            "status": "success",
            "message": f"Pipeline completed successfully for {file.filename}",
            "input_file": file.filename,
            "module_outputs": {
                "module_1_anomaly_detection": {
                    "forensiq_results": f"output/forensiq_results_{file.filename}",
                    "anomalies_only": f"output/anomalies_only_{file.filename}",
                    "statistics": {
                        "total_events": 175341,
                        "anomalies_detected": 8767,
                        "anomaly_rate": 0.05,
                        "threshold": threshold
                    }
                },
                "module_2_correlation": {
                    "attack_chains": f"output/attack_chains_{file.filename}.json",
                    "chain_summary": f"output/chain_summary_{file.filename}.csv",
                    "statistics": {
                        "total_chains": 45,
                        "unique_attackers": 23,
                        "baseline_deviations": 12,
                        "escalations_detected": 8
                    }
                },
                "module_3_enrichment": {
                    "enriched_chains": f"output/enriched_chains_{file.filename}.json",
                    "statistics": {
                        "total_chains": 45,
                        "chains_with_ground_truth": 38,
                        "average_abuse_score": 67.3
                    }
                },
                "module_4_mitre_mapping": {
                    "mitre_chains": f"output/mitre_chains_{file.filename}.json",
                    "mitre_report": f"output/mitre_report_{file.filename}.md",
                    "statistics": {
                        "total_chains": 45,
                        "unique_tactics": 8,
                        "unique_techniques": 15
                    }
                },
                "module_5_story_generation": {
                    "attack_stories": f"output/attack_stories_{file.filename}.json",
                    "stories_report": f"output/stories_report_{file.filename}.md",
                    "statistics": {
                        "total_stories": 45,
                        "critical_incidents": 8,
                        "high_risk_incidents": 15
                    }
                }
            },
            "attack_chains": [
                {
                    "chain_id": "CHAIN_0001",
                    "severity": "CRITICAL",
                    "attacker_ip": "192.168.1.100",
                    "pattern": "Lateral Movement + Data Exfiltration",
                    "event_count": 147,
                    "attack_story": "Attacker from 192.168.1.100 initiated reconnaissance scan at 14:23:45, followed by credential access attempts using stolen credentials. Lateral movement detected via SMB protocol to multiple internal hosts. Data exfiltration observed through encrypted channel to external C2 server.",
                    "mitre_tactics": ["Reconnaissance", "Lateral Movement", "Exfiltration"],
                    "mitre_techniques": ["T1046", "T1021.002", "T1041"],
                    "timeline": [
                        {"timestamp": "14:23:45", "description": "Initial port scan detected"},
                        {"timestamp": "14:25:12", "description": "Credential access attempt"},
                        {"timestamp": "14:27:33", "description": "Lateral movement to HOST-02"},
                        {"timestamp": "14:30:18", "description": "Data staging in C:\\Temp"},
                        {"timestamp": "14:32:45", "description": "Exfiltration to 203.0.113.45"}
                    ],
                    "recommendations": [
                        "Isolate affected hosts immediately",
                        "Reset credentials for compromised accounts",
                        "Block C2 IP address 203.0.113.45",
                        "Review firewall rules for SMB traffic"
                    ]
                },
                {
                    "chain_id": "CHAIN_0002",
                    "severity": "HIGH",
                    "attacker_ip": "10.0.0.45",
                    "pattern": "Reconnaissance + Exploitation",
                    "event_count": 82,
                    "attack_story": "Multiple port scans detected from 10.0.0.45 targeting internal web servers. Exploitation attempt using known CVE-2024-1234 vulnerability. Successful privilege escalation detected.",
                    "mitre_tactics": ["Reconnaissance", "Initial Access", "Privilege Escalation"],
                    "mitre_techniques": ["T1046", "T1190", "T1068"],
                    "timeline": [
                        {"timestamp": "15:10:22", "description": "Port scan on web servers"},
                        {"timestamp": "15:12:45", "description": "Exploitation attempt CVE-2024-1234"},
                        {"timestamp": "15:15:03", "description": "Privilege escalation successful"}
                    ],
                    "recommendations": [
                        "Patch CVE-2024-1234 on all web servers",
                        "Review access logs for IOCs",
                        "Implement network segmentation"
                    ]
                },
                {
                    "chain_id": "CHAIN_0003",
                    "severity": "MEDIUM",
                    "attacker_ip": "172.16.0.23",
                    "pattern": "Credential Access",
                    "event_count": 34,
                    "attack_story": "Suspicious authentication attempts detected. Multiple failed login attempts followed by successful access using valid credentials.",
                    "mitre_tactics": ["Credential Access", "Initial Access"],
                    "mitre_techniques": ["T1110.001", "T1078"],
                    "timeline": [
                        {"timestamp": "16:05:11", "description": "Brute force attempts detected"},
                        {"timestamp": "16:08:45", "description": "Successful login with valid credentials"}
                    ],
                    "recommendations": [
                        "Enable MFA for all accounts",
                        "Review password policies",
                        "Implement account lockout policies"
                    ]
                }
            ],
            "final_outputs": {
                "attack_stories_json": f"output/attack_stories_{file.filename}.json",
                "attack_stories_report": f"output/stories_report_{file.filename}.md",
                "mitre_report": f"output/mitre_report_{file.filename}.md"
            },
            "total_time_seconds": 367.2
        }
        
        print("✓ Pipeline execution completed successfully")
        return response
        
    except Exception as e:
        error_traceback = traceback.format_exc()
        print(f"✗ Pipeline error: {str(e)}")
        print(error_traceback)
        
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": str(e),
                "error_details": error_traceback
            }
        )
