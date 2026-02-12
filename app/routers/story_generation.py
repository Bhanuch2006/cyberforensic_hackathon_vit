"""
Attack Story Generation Router - Module 5
"""
from fastapi import APIRouter, HTTPException
from app.models.requests import StoryGenerationRequest
from app.models.responses import StoryGenerationResponse
from app.services.story_generator import story_generator

router = APIRouter(
    prefix="/api/v1",
    tags=["Story Generation"]
)


@router.post("/generate-stories", response_model=StoryGenerationResponse)
async def generate_attack_stories(request: StoryGenerationRequest):
    """
    Generate human-readable attack narratives
    
    **Module 5: Attack Story Generation**
    
    Creates comprehensive incident narratives from technical data, including:
    - Executive summaries
    - Detailed attack narratives
    - Incident timelines
    - Risk assessments
    - Security recommendations
    - MITRE ATT&CK context
    
    **Input:**
    - mitre_chains_file: enriched_chains_{timestamp}_ground_truth_mitre.json from Module 4
    
    **Output:**
    - enriched_chains_{timestamp}_ground_truth_stories.json: Chains with narratives
    - attack_stories_report_{timestamp}.md: Markdown report
    
    **Example:**
    ```json
    {
        "mitre_chains_file": "output/enriched_chains_20260203_ground_truth_mitre.json"
    }
    ```
    """
    try:
        result = await story_generator.generate_stories(
            mitre_chains_file=request.mitre_chains_file
        )
        
        return StoryGenerationResponse(
            status="success",
            message=f"Story generation completed. Generated {result['statistics']['total_stories']} narratives.",
            output_files=result['output_files'],
            statistics=result['statistics']
        )
    
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=f"File not found: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Story generation failed: {str(e)}")
