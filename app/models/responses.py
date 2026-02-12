"""
Pydantic response models
"""

from pydantic import BaseModel, Field, ConfigDict
from typing import Dict, List, Any, Optional
from datetime import datetime

class AnomalyDetectionResponse(BaseModel):
    """Response for anomaly detection"""
    status: str
    message: str
    output_files: Dict[str, str]
    statistics: Dict[str, any]


class CorrelationResponse(BaseModel):
    """Response for correlation engine"""
    status: str
    message: str
    output_files: Dict[str, str]
    statistics: Dict[str, any]


class EnrichmentResponse(BaseModel):
    """Response for IP enrichment"""
    status: str
    message: str
    output_file: str
    statistics: Dict[str, any]


class MITREMappingResponse(BaseModel):
    """Response for MITRE mapping"""
    status: str
    message: str
    output_files: Dict[str, str]
    statistics: Dict[str, any]


class StoryGenerationResponse(BaseModel):
    """Response for story generation"""
    status: str
    message: str
    output_files: Dict[str, str]
    statistics: Dict[str, any]


class FullPipelineResponse(BaseModel):
    """Response for full pipeline"""
    status: str
    message: str
    module_outputs: Dict[str, Dict[str, str]]
    final_outputs: Dict[str, str]
    total_time_seconds: float
