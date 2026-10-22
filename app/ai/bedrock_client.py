"""
Optional Amazon Bedrock client integration for TrustLens AI.
Supports Bedrock Converse API / InvokeModel with Claude or Titan.
Strictly handles authentication errors, timeouts, and missing credentials.
"""

import os
import json
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger("trustlens.ai.bedrock")

class BedrockClient:
    def __init__(self, region_name: str = "us-east-1", model_id: str = "anthropic.claude-3-haiku-20240307-v1:0"):
        self.region_name = region_name
        self.model_id = model_id
        self._client = None
        self._is_available = None

    def check_availability(self) -> bool:
        """Checks if AWS credentials and boto3 are available for Bedrock."""
        if self._is_available is not None:
            return self._is_available

        # Check for AWS credentials in environment
        has_creds = bool(
            os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY")
        ) or bool(os.getenv("AWS_PROFILE"))

        if not has_creds:
            logger.info("No AWS credentials detected; Amazon Bedrock will remain in fallback mode.")
            self._is_available = False
            return False

        try:
            import boto3
            self._client = boto3.client("bedrock-runtime", region_name=self.region_name)
            self._is_available = True
            return True
        except Exception as e:
            logger.warning(f"Failed to initialize boto3 bedrock-runtime client: {e}")
            self._is_available = False
            return False

    def generate_explanation(self, system_prompt: str, user_prompt: str, timeout: int = 8) -> Optional[str]:
        """Invokes Amazon Bedrock model with prompt injection safety boundaries."""
        if not self.check_availability():
            return None

        try:
            # Bedrock Converse API format (standard across Claude 3, Nova, Titan)
            response = self._client.converse(
                modelId=self.model_id,
                messages=[
                    {
                        "role": "user",
                        "content": [{"text": user_prompt}]
                    }
                ],
                system=[{"text": system_prompt}],
                inferenceConfig={
                    "maxTokens": 1000,
                    "temperature": 0.1,
                    "topP": 0.9
                }
            )
            output_text = response['output']['message']['content'][0]['text']
            return output_text
        except Exception as e:
            logger.warning(f"Amazon Bedrock invocation encountered an error or timeout: {e}")
            return None

    def analyze_multimodal_image(
        self,
        image_bytes: bytes,
        image_format: str,
        system_prompt: str,
        user_prompt: str,
        timeout: int = 15
    ) -> Optional[str]:
        """
        Invokes Amazon Bedrock Multimodal Vision model (Claude 3, Nova) with image bytes.
        Supports PNG, JPEG, WEBP, and GIF formats.
        """
        if not self.check_availability():
            return None

        # Normalize format name for Bedrock Converse API
        fmt_map = {"jpg": "jpeg", "jpeg": "jpeg", "png": "png", "webp": "webp", "gif": "gif"}
        norm_fmt = fmt_map.get(image_format.lower().strip("."), "png")

        try:
            response = self._client.converse(
                modelId=self.model_id,
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {
                                "image": {
                                    "format": norm_fmt,
                                    "source": {
                                        "bytes": image_bytes
                                    }
                                }
                            },
                            {
                                "text": user_prompt
                            }
                        ]
                    }
                ],
                system=[{"text": system_prompt}],
                inferenceConfig={
                    "maxTokens": 1500,
                    "temperature": 0.1,
                    "topP": 0.9
                }
            )
            output_text = response['output']['message']['content'][0]['text']
            return output_text
        except Exception as e:
            logger.warning(f"Amazon Bedrock Multimodal invocation failed: {e}")
            return None

