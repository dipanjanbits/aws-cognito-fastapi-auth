# AWS Cognito FastAPI Authentication System

This project implements a secure authentication system using AWS Cognito with FastAPI backend and Streamlit frontend. It provides a complete solution for token generation, validation, and API security.

## Project Structure

```
aws-cognito-fastapi-auth/
├── fastapi/
│   ├── main.py              # FastAPI backend server
│   └── requirements.txt     # Backend dependencies
├── streamlit/
│   ├── cognito_token_generator.py    # Streamlit frontend for token generation
│   └── requirements.txt              # Frontend dependencies
└── README.md
```

## Features

- **FastAPI Backend**:
  - Secure JWT token validation
  - AWS Lambda integration
  - CORS middleware support
  - Role-based authentication
  - Automatic AWS credential management

- **Streamlit Frontend**:
  - User-friendly token generation interface
  - JWT token decoder and validator
  - Token information display
  - Copy-to-clipboard functionality
  - Beautiful UI with custom styling

## Prerequisites

- Python 3.7+
- AWS Account with Cognito User Pool configured
- AWS CLI configured with appropriate credentials
- Virtual environment management tool (recommended)

## Setup and Installation

### Backend Setup (FastAPI)

1. Create and activate a virtual environment:
```bash
cd fastapi
python -m venv .venv
.venv\Scripts\activate  # On Windows
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure environment variables:
Create a `.env` file in the `fastapi` directory with the following variables:
```env
AWS_REGION=<your-aws-region>
JWT_ISSUER=<your-cognito-user-pool-url>
JWT_AUDIENCE=<your-app-client-id>
JWKS_URL=<your-cognito-jwks-url>
```

4. Run the FastAPI server:
```bash
uvicorn main:app --reload
```

### Frontend Setup (Streamlit)

1. Create and activate a virtual environment:
```bash
cd streamlit
python -m venv .venv
.venv\Scripts\activate  # On Windows
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the Streamlit app:
```bash
streamlit run cognito_token_generator.py
```

## Usage

1. **Token Generation**:
   - Navigate to the Streamlit frontend
   - Enter your AWS Cognito credentials
   - Generate and view tokens
   - Copy tokens for API usage

2. **API Authentication**:
   - Use the generated token in the Authorization header
   - Format: `Bearer <your-token>`
   - Access protected API endpoints

## Security Features

- JWT token validation
- AWS IAM role-based authentication
- Secure credential management
- CORS protection
- Environment variable configuration
- Token expiration handling

## Development

The project uses modern Python practices and follows these principles:
- Type hints for better code quality
- Comprehensive error handling
- Asynchronous operations where beneficial
- Clean code architecture
- Modular design

## Contributing

1. Fork the repository
2. Create a new branch for your feature
3. Submit a pull request with a clear description of your changes

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions, please open an issue in the repository.