"""
MITRE ATT&CK Mapping Router - Module 4
"""
from fastapi import APIRouter, HTTPException
from app.models.requests import MITREMappingRequest
from app.models.responses import MITREMappingResponse
from app.services.mitre_mapper import mitre_mapper

router = APIRouter(
    prefix="/api/v1",
    tags=["MITRE ATT&CK Mapping"]
)


@router.post("/map-mitre", response_model=MITREMappingResponse)
async def map_mitre_attack(request: MITREMappingRequest):
    """
    Map attack chains to MITRE ATT&CK framework
    
    **Module 4: MITRE ATT&CK Mapping**
    
    Maps attack chains to industry-standard MITRE ATT&CK framework, providing:
    - Tactic identification (e.g., Reconnaissance, Initial Access)
    - Technique mapping with confidence scores
    - Sub-technique categorization
    - Cyber Kill Chain phase classification
    - Evidence extraction
    
    **Input:**
    - enriched_chains_file: enriched_chains_{timestamp}_ground_truth.json from Module 3
    
    **Output:**
    - enriched_chains_{timestamp}_ground_truth_mitre.json: Chains with MITRE mapping
    - mitre_attack_report_{timestamp}.md: Markdown report
    
    **Example:**
    ```json
    {
        "enriched_chains_file": "output/enriched_chains_20260203_ground_truth.json"
    }
    ```
    """
    try:
        result = await mitre_mapper.map_chains(
            enriched_chains_file=request.enriched_chains_file
        )
        
        return MITREMappingResponse(
            status="success",
            message=f"MITRE mapping completed. Mapped {result['statistics']['total_chains']} chains.",
            output_files=result['output_files'],
            statistics=result['statistics']
        )
    
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=f"File not found: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"MITRE mapping failed: {str(e)}")
