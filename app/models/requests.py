"""
Pydantic request models
"""
from pydantic import BaseModel, Field
from typing import Optional


class AnomalyDetectionRequest(BaseModel):
    """Request for anomaly detection"""
    input_file: str = Field(..., description="Path to input CSV file")
    threshold: Optional[float] = Field(None, description="Custom anomaly threshold (auto-calculated if not provided)")


class CorrelationRequest(BaseModel):
    """Request for correlation engine"""
    full_results_file: str = Field(..., description="Path to forensiq_results CSV")
    anomalies_file: str = Field(..., description="Path to anomalies_only CSV")


class EnrichmentRequest(BaseModel):
    """Request for IP enrichment"""
    chains_file: str = Field(..., description="Path to attack chains JSON")
    dataset_file: str = Field(..., description="Path to UNSW dataset for ground truth")


class MITREMappingRequest(BaseModel):
    """Request for MITRE ATT&CK mapping"""
    enriched_chains_file: str = Field(..., description="Path to enriched chains JSON")


class StoryGenerationRequest(BaseModel):
    """Request for story generation"""
    mitre_chains_file: str = Field(..., description="Path to MITRE-mapped chains JSON")


class FullPipelineRequest(BaseModel):
    """Request for full pipeline execution"""
    input_file: str = Field(..., description="Path to input CSV file")
    threshold: Optional[float] = Field(None, description="Custom anomaly threshold")
