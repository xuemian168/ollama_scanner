# Ollama Scanner

A command-line tool for scanning and interacting with Ollama services across networks.

## Disclaimer

This software is for testing and educational purposes only. By using this software, you agree:

- To use it only for legitimate testing purposes with proper authorization
- Not to use it for any malicious or illegal activities
- Not to scan networks or systems without explicit permission
- The author bears no responsibility for any misuse or damage caused by this tool

**Use at your own risk and responsibility.**

## Features

- Scan single IP or network ranges for Ollama services
- Display detailed information about discovered Ollama instances
- List installed models and their specifications
- Interactive chat with available models
- Progress bar for network scanning
- Automatic retry mechanism for unstable connections
- Streaming responses for real-time model interactions

## APIs

•	**/api/generate** is used to generate text or content. It is typically used to produce responses or outputs based on given input, such as generating conversation replies or articles.

•	**/api/chat** is specifically for chat interactions. Users can interact with the model through this endpoint, and the model will generate corresponding responses based on the input.

•	**/api/create** is used to create new models or resources. This may involve initializing a new model instance or configuration.

•	**/api/tags** is used to manage or view model tags. Tags help users categorize or label models for easier management and retrieval.

•	**/api/show** is used to display detailed information about a model or resource. Users can retrieve model configurations, statuses, or other relevant details.

•	**/api/copy** is used to duplicate a model or resource. Users can create a copy of an existing model through this endpoint.

•	**/api/delete** is used to delete a model or resource. Users can remove models or data that are no longer needed via this endpoint.

•	**/api/pull** is used to download a model from **Ollama**. Users can pull a model from a remote server to their local environment using this endpoint.

•	**/api/push** is used to upload a model to **Ollama**. Users can push a local model to a remote server through this endpoint.

•	**/api/embeddings** is used to generate text embeddings. Embeddings are numerical representations of text, commonly used for feature extraction in machine learning tasks.

•	**/api/version** is used to retrieve **Ollama** version information. Users can query this endpoint to check the current version of **Ollama** in use.
