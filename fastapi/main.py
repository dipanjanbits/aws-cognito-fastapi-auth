
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import os
import uvicorn
import boto3
import json
import jwt
from jwt import PyJWKClient
import logging
from typing import Optional, Dict, Any
from functools import wraps
import asyncio
from concurrent.futures import ThreadPoolExecutor

from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="AWS Cloud Migration AI Assistant Backend",
    description="Backend service for AWS Cloud Migration AI Assistant",
    version="0.0.1"
)

# CORS settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust as needed for security
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Security
security = HTTPBearer()

# Configuration
class Config:
    # AWS Configuration
    AWS_REGION = os.getenv("AWS_REGION")
    LAMBDA_FUNCTION_NAME = os.getenv("LAMBDA_FUNCTION_NAME")
    
    # JWT Configuration (for Cognito/Auth0/etc.)
    JWT_ISSUER = os.getenv("JWT_ISSUER", "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_e7Lr8DWuw")
    JWT_AUDIENCE = os.getenv("JWT_AUDIENCE")  # Set this to your Cognito App Client ID
    JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "RS256")
    JWKS_URL = os.getenv("JWKS_URL", "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_e7Lr8DWuw/.well-known/jwks.json")

config = Config()

# JWT client for token verification
jwks_client = PyJWKClient(config.JWKS_URL) if config.JWKS_URL else None

# Thread pool for async AWS operations
executor = ThreadPoolExecutor(max_workers=10)

class AWSClientManager:
    """Manages AWS clients with IAM role-based authentication"""
    
    def __init__(self):
        self._lambda_client = None
        self._s3_client = None
        self._session = None
        self._initialize_session()
    
    def _initialize_session(self):
        """Initialize boto3 session with IAM role"""
        try:
            # When running in ECS/EKS, boto3 automatically uses the task/pod IAM role
            self._session = boto3.Session()
            logger.info("AWS session initialized with IAM role")
        except Exception as e:
            logger.error(f"Failed to initialize AWS session: {e}")
            raise
    
    @property
    def lambda_client(self):
        """Get Lambda client with role-based authentication"""
        if not self._lambda_client:
            self._lambda_client = self._session.client("lambda", region_name=config.AWS_REGION)
        return self._lambda_client
    
    # @property
    # def s3_client(self):
    #     """Get S3 client with role-based authentication"""
    #     if not self._s3_client:
    #         self._s3_client = self._session.client("s3", region_name=config.AWS_REGION)
    #     return self._s3_client
    
    def refresh_credentials(self):
        """Refresh AWS credentials (useful for long-running applications)"""
        self._lambda_client = None
        # self._s3_client = None
        self._initialize_session()

# Global AWS client manager
aws_manager = AWSClientManager()

class JWTBearer:
    """JWT token authentication and authorization"""
    
    def __init__(self, required_roles: Optional[list] = None):
        self.required_roles = required_roles or []
    
    
    async def verify_token(self, credentials: HTTPAuthorizationCredentials) -> Dict[str, Any]:
        """Verify JWT token and extract claims"""
        try:
            if not jwks_client:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="JWT verification not configured"
                )
            
            token = credentials.credentials
            
            # First decode without verification to check claims
            unverified_headers = jwt.get_unverified_header(token)
            unverified_claims = jwt.decode(token, options={"verify_signature": False})
            
            # Get signing key
            try:
                signing_key = jwks_client.get_signing_key_from_jwt(token)
            except Exception as e:
                logger.error(f"Failed to get signing key: {e}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token signature"
                )
            
            # Verify and decode token
            try:
                payload = jwt.decode(
                    token,
                    signing_key.key,
                    algorithms=[config.JWT_ALGORITHM],
                    audience=config.JWT_AUDIENCE,  # This is your App Client ID
                    issuer=config.JWT_ISSUER,
                    options={
                        "verify_signature": True,
                        "verify_aud": True,
                        "verify_iss": True,
                        "verify_exp": True
                    }
                )
                logger.info(f"Token verified successfully for user: {payload.get('sub')}")
                return payload
                
            except jwt.ExpiredSignatureError:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has expired"
                )
            except jwt.InvalidAudienceError:
                logger.error(f"Invalid audience. Expected: {config.JWT_AUDIENCE}, Got: {unverified_claims.get('aud')}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token audience"
                )
            except jwt.InvalidTokenError as e:
                logger.error(f"Invalid token: {e}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=str(e)
                )
                
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials"
            )
        
    

    
    def check_roles(self, user_payload: Dict[str, Any]) -> bool:
        """Check if user has required roles"""
        if not self.required_roles:
            return True
        
        # Extract roles from token (adjust based on your JWT structure)
        user_roles = user_payload.get("cognito:groups", [])  # For Cognito
        # or user_roles = user_payload.get("roles", [])  # For Auth0/other providers
        
        return any(role in user_roles for role in self.required_roles)
# Dependency functions
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """Get current authenticated user"""
    jwt_bearer = JWTBearer()
    return await jwt_bearer.verify_token(credentials)

def require_roles(required_roles: list):
    """Dependency factory for role-based access control"""
    async def role_checker(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
        jwt_bearer = JWTBearer(required_roles)
        user_payload = await jwt_bearer.verify_token(credentials)
        
        if not jwt_bearer.check_roles(user_payload):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required roles: {required_roles}"
            )
        
        return user_payload
    
    return role_checker
# Async wrapper for AWS operations
async def invoke_lambda_async(function_name: str, payload: dict) -> dict:
    """Async wrapper for Lambda invocation"""
    loop = asyncio.get_event_loop()
    
    def _invoke():
        response = aws_manager.lambda_client.invoke(
            FunctionName=function_name,
            InvocationType="RequestResponse",
            Payload=json.dumps(payload)
        )
        return json.loads(response["Payload"].read().decode("utf-8"))
    
    return await loop.run_in_executor(executor, _invoke)

# async def s3_operation_async(operation: str, bucket: str, key: str = None, **kwargs) -> dict:
#     """Async wrapper for S3 operations"""
#     loop = asyncio.get_event_loop()
    
#     def _s3_operation():
#         if operation == "list_objects":
#             response = aws_manager.s3_client.list_objects_v2(Bucket=bucket, **kwargs)
#         elif operation == "get_object" and key:
#             response = aws_manager.s3_client.get_object(Bucket=bucket, Key=key, **kwargs)
#         elif operation == "put_object" and key:
#             response = aws_manager.s3_client.put_object(Bucket=bucket, Key=key, **kwargs)
#         else:
#             raise ValueError(f"Unsupported S3 operation: {operation}")
        
#         return response
    
#     return await loop.run_in_executor(executor, _s3_operation)

@app.get("/health")
async def health_check():
    return {"status": "ok", "message": "FastAPI service is healthy"}

@app.get("/protected-health")
async def protected_health_check(current_user: dict = Depends(get_current_user)):
    """Protected health check endpoint"""
    return {
        "status": "ok", 
        "message": "Protected FastAPI service is healthy",
        "user": current_user.get("sub", "unknown")
    }

@app.get("/aws_health")
async def call_lambda(
    name: str = "Guest",
    current_user: dict = Depends(get_current_user)
):
    """Call Lambda function with user authentication"""
    try:
        # Create event with user context
        event = {
            "queryStringParameters": {"name": name},
            "requestContext": {
                "authorizer": {
                    "claims": {
                        "sub": current_user.get("sub"),
                        "email": current_user.get("email"),
                        "cognito:groups": current_user.get("cognito:groups", [])
                    }
                }
            }
        }
        
        # Invoke Lambda asynchronously
        response = await invoke_lambda_async(config.LAMBDA_FUNCTION_NAME, event)
        
        # Parse response
        if "body" in response:
            body = json.loads(response["body"]) if isinstance(response["body"], str) else response["body"]
        else:
            body = response
        
        return {"lambda_result": body, "user": current_user.get("email", "unknown")}
        
    except Exception as e:
        logger.error(f"Lambda invocation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to invoke Lambda function: {str(e)}"
        )

# @app.get("/admin/lambda")
# async def admin_lambda_call(
#     name: str = "Admin",
#     current_user: dict = Depends(require_roles(["admin", "superuser"]))
# ):
#     """Admin-only Lambda function call"""
#     try:
#         event = {
#             "queryStringParameters": {"name": name, "admin": "true"},
#             "requestContext": {
#                 "authorizer": {
#                     "claims": current_user
#                 }
#             }
#         }
        
#         response = await invoke_lambda_async(config.LAMBDA_FUNCTION_NAME, event)
#         body = json.loads(response["body"]) if "body" in response else response
        
#         return {
#             "lambda_result": body, 
#             "admin_user": current_user.get("email", "unknown"),
#             "roles": current_user.get("cognito:groups", [])
#         }
        
#     except Exception as e:
#         logger.error(f"Admin Lambda invocation error: {e}")
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail=f"Failed to invoke Lambda function: {str(e)}"
#         )
        
# @app.get("/s3/buckets")
# async def list_s3_buckets(current_user: dict = Depends(get_current_user)):
#     """List S3 buckets (example S3 integration)"""
#     try:
#         response = await s3_operation_async("list_objects", "your-bucket-name")
        
#         return {
#             "buckets": response.get("Contents", []),
#             "user": current_user.get("email", "unknown")
#         }
        
#     except Exception as e:
#         logger.error(f"S3 operation error: {e}")
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail=f"Failed to perform S3 operation: {str(e)}"
#         )
        
@app.post("/refresh-aws-credentials")
async def refresh_aws_credentials(
    current_user: dict = Depends(require_roles(["admin"]))
):
    """Refresh AWS credentials (admin only)"""
    try:
        aws_manager.refresh_credentials()
        return {
            "status": "success",
            "message": "AWS credentials refreshed",
            "admin": current_user.get("email", "unknown")
        }
    except Exception as e:
        logger.error(f"Failed to refresh AWS credentials: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to refresh credentials: {str(e)}"
        )

@app.get("/user/profile")
async def get_user_profile(current_user: dict = Depends(get_current_user)):
    """Get current user profile"""
    return {
        "user_id": current_user.get("sub"),
        "email": current_user.get("email"),
        "roles": current_user.get("cognito:groups", []),
        "name": current_user.get("name", current_user.get("given_name", "Unknown"))
    }        
                
if __name__ == "__main__":
    # Validate configuration
    if not all([config.JWT_ISSUER, config.JWT_AUDIENCE, config.JWKS_URL]):
        logger.warning("JWT configuration incomplete. Some endpoints may not work.")
    
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=int(os.getenv("PORT", 8000)),
        log_level="info"
    )