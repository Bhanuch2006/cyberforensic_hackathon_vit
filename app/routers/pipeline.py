"""
Full Pipeline Router
Executes all modules sequentially
"""
from fastapi import APIRouter, HTTPException
from app.models.requests import FullPipelineRequest
from app.models.responses import FullPipelineResponse
from app.services.anomaly_detector import anomaly_detection_service
from app.services.correlation_engine import correlation_engine
from app.services.ip_enricher import ip_enrichment_service
from app.services.mitre_mapper import mitre_mapper
from app.services.story_generator import story_generator
import time

router = APIRouter(
    prefix="/api/v1",
    tags=["Full Pipeline"]
)


@router.post("/run-full-pipeline", response_model=FullPipelineResponse)
async def run_full_pipeline(request: FullPipelineRequest):
    """
    Execute complete ForensIQ pipeline (all 5 modules)
    
    **Full Pipeline Execution**
    
    Runs all modules sequentially:
    1. Anomaly Detection (ML inference)
    2. Correlation Engine (attack chain building)
    3. IP Enrichment (reputation scoring)
    4. MITRE ATT&CK Mapping (framework alignment)
    5. Attack Story Generation (narrative creation)
    
    **Input:**
    - input_file: Path to CSV file with network traffic data
    - threshold: Optional anomaly threshold (default: 0.5)
    
    **Output:**
    - All intermediate and final output files from each module
    - Complete attack narratives with MITRE mapping and recommendations
    
    **Example:**
    ```json
    {
        "input_file": "data/UNSW_prepared.csv",
        "threshold": 0.5
    }
    ```
    
    **Note:** This endpoint may take several minutes depending on dataset size.
    """
    start_time = time.time()
    module_outputs = {}
    
    try:
        print("\n" + "="*80)
        print("🚀 ForensIQ Full Pipeline Execution")
        print("="*80)
        
        # Module 1: Anomaly Detection
        print("\n[1/5] Running Anomaly Detection...")
        module1_result = await anomaly_detection_service.detect_anomalies(
            input_file=request.input_file,
            threshold=request.threshold
        )
        module_outputs['module_1_anomaly_detection'] = module1_result['output_files']
        
        forensiq_results = module1_result['output_files']['forensiq_results']
        anomalies_only = module1_result['output_files']['anomalies_only']
        
        print(f"✅ Module 1 complete. Detected {module1_result['statistics']['anomalies_detected']} anomalies.")
        
        # Module 2: Correlation
        print("\n[2/5] Running Correlation Engine...")
        module2_result = await correlation_engine.correlate(
            full_results_file=forensiq_results,
            anomaly_file=anomalies_only
        )
        module_outputs['module_2_correlation'] = module2_result['output_files']
        
        attack_chains = module2_result['output_files']['attack_chains']
        
        print(f"✅ Module 2 complete. Created {module2_result['statistics']['total_chains']} attack chains.")
        
        # Module 3: IP Enrichment
        print("\n[3/5] Running IP Enrichment...")
        module3_result = await ip_enrichment_service.enrich_chains(
            chains_file=attack_chains,
            dataset_file=request.input_file
        )
        module_outputs['module_3_enrichment'] = module3_result['output_files']
        
        enriched_chains = module3_result['output_files']['enriched_chains']
        
        print(f"✅ Module 3 complete. Enriched {module3_result['statistics']['total_chains']} chains.")
        
        # Module 4: MITRE Mapping
        print("\n[4/5] Running MITRE ATT&CK Mapping...")
        module4_result = await mitre_mapper.map_chains(
            enriched_chains_file=enriched_chains
        )
        module_outputs['module_4_mitre_mapping'] = module4_result['output_files']
        
        mitre_chains = module4_result['output_files']['mitre_chains']
        
        print(f"✅ Module 4 complete. Mapped {module4_result['statistics']['total_chains']} chains.")
        
        # Module 5: Story Generation
        print("\n[5/5] Running Attack Story Generation...")
        module5_result = await story_generator.generate_stories(
            mitre_chains_file=mitre_chains
        )
        module_outputs['module_5_story_generation'] = module5_result['output_files']
        
        print(f"✅ Module 5 complete. Generated {module5_result['statistics']['total_stories']} stories.")
        
        total_time = time.time() - start_time
        
        print("\n" + "="*80)
        print("✅ FULL PIPELINE COMPLETE")
        print("="*80)
        print(f"⏱️  Total execution time: {total_time:.1f}s")
        print(f"📦 Final output: {module5_result['output_files']['attack_stories']}")
        
        return FullPipelineResponse(
            status="success",
            message=f"Full pipeline completed successfully in {total_time:.1f}s",
            module_outputs=module_outputs,
            final_outputs={
                "attack_stories_json": module5_result['output_files']['attack_stories'],
                "attack_stories_report": module5_result['output_files']['stories_report'],
                "mitre_report": module4_result['output_files']['mitre_report']
            },
            total_time_seconds=round(total_time, 2)
        )
    
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=f"File not found: {str(e)}")
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Pipeline execution failed at stage {len(module_outputs)+1}: {str(e)}"
        )
