import google.generativeai as genai
import logging
from typing import Optional, List, Dict, Any

# Configure logging
logger = logging.getLogger(__name__)

class GeminiClient:
    """A wrapper class for the Google Generative AI client."""

    def __init__(
        self, 
        api_key: str, 
        model_name: str,
        tools: Optional[List[Any]] = None, # Adjust 'Any' based on google.generativeai.types.Tool if possible 
        safety_settings: Optional[Dict[str, str]] = None,
        tool_config: Optional[Dict[str, str]] = None
    ):
        """
        Initializes the Gemini client.

        Args:
            api_key: The Google API key.
            model_name: The name of the Gemini model to use (e.g., 'models/gemini-1.5-pro-latest').
            tools: Optional list of tools (e.g., FunctionDeclarations) for the model.
            safety_settings: Optional dictionary of safety settings.
            tool_config: Optional dictionary for tool configuration (e.g., function calling mode).
        """
        if not api_key:
            raise ValueError("API key is required for GeminiClient.")
        if not model_name:
             raise ValueError("Model name is required for GeminiClient.")

        self.model_name = model_name
        
        try:
            logger.debug(f"Configuring Gemini API key.")
            genai.configure(api_key=api_key)
            
            logger.debug(f"Initializing Gemini model: {self.model_name}")
            # Prepare arguments, only passing them if they are not None
            model_kwargs = {"model_name": self.model_name}
            if safety_settings:
                model_kwargs["safety_settings"] = safety_settings
            if tools:
                model_kwargs["tools"] = tools
            if tool_config:
                 model_kwargs["tool_config"] = tool_config
                 
            self.model = genai.GenerativeModel(**model_kwargs)
            logger.debug(f"Gemini model '{self.model_name}' initialized successfully.")

        except Exception as e:
            logger.error(f"Failed to initialize model")
            raise ConnectionError(f"Failed to initialize model") from e

    def generate_content(self, prompt: str, **kwargs) -> Any: # Adjust 'Any' to actual response type
        """
        Generates content using the initialized Gemini model.

        Args:
            prompt: The prompt string to send to the model.
            **kwargs: Additional arguments to pass to the model's generate_content method.

        Returns:
            The response object from the Gemini API. Adjust type hint as needed.
            
        Raises:
            Exception: If the API call fails.
        """
        if not self.model:
            raise RuntimeError("Gemini model is not initialized.")
            
        logger.debug(f"Sending prompt to Gemini model '{self.model_name}'. Prompt length: {len(prompt)}")
        try:
            response = self.model.generate_content(prompt, **kwargs)
            return response
        except Exception as e:
            logger.error(f"API call failed")
            raise
