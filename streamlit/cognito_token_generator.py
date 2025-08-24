import streamlit as st
import boto3
import json
import jwt
from datetime import datetime, timedelta
import base64
import requests
from botocore.exceptions import ClientError, NoCredentialsError
import pyperclip
import hmac
import hashlib

# Set page config
st.set_page_config(
    page_title="AWS Cognito Token Generator",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .success-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        color: #155724;
        margin: 1rem 0;
    }
    .error-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        color: #721c24;
        margin: 1rem 0;
    }
    .info-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #d1ecf1;
        border: 1px solid #bee5eb;
        color: #0c5460;
        margin: 1rem 0;
    }
    .token-box {
        background-color: #f8f9fa;
        border: 1px solid #dee2e6;
        border-radius: 0.5rem;
        padding: 1rem;
        font-family: monospace;
        font-size: 0.8rem;
        word-break: break-all;
        max-height: 200px;
        overflow-y: auto;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'token_data' not in st.session_state:
    st.session_state.token_data = {}

if 'cognito_config' not in st.session_state:
    st.session_state.cognito_config = {}

def decode_token(token):
    """Decode JWT token without verification for display purposes"""
    try:
        # Split the token
        parts = token.split('.')
        if len(parts) != 3:
            return None, "Invalid JWT format"
        
        # Decode header and payload
        header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
        
        return {'header': header, 'payload': payload}, None
    except Exception as e:
        return None, f"Error decoding token: {str(e)}"

def get_token_info(token_data):
    """Extract useful information from decoded token"""
    if not token_data:
        return {}
    
    payload = token_data.get('payload', {})
    
    info = {
        'username': payload.get('username', 'N/A'),
        'email': payload.get('email', 'N/A'),
        'client_id': payload.get('aud', 'N/A'),
        'issued_at': datetime.fromtimestamp(payload.get('iat', 0)).strftime('%Y-%m-%d %H:%M:%S') if payload.get('iat') else 'N/A',
        'expires_at': datetime.fromtimestamp(payload.get('exp', 0)).strftime('%Y-%m-%d %H:%M:%S') if payload.get('exp') else 'N/A',
        'token_use': payload.get('token_use', 'N/A'),
        'groups': payload.get('cognito:groups', []),
        'scope': payload.get('scope', '').split() if payload.get('scope') else []
    }
    
    # Calculate time until expiration
    if payload.get('exp'):
        exp_time = datetime.fromtimestamp(payload.get('exp'))
        now = datetime.now()
        if exp_time > now:
            time_left = exp_time - now
            info['time_left'] = f"{time_left.seconds // 60} minutes"
            info['expired'] = False
        else:
            info['expired'] = True
            info['time_left'] = "Expired"
    
    return info

def calculate_secret_hash(username, client_id, client_secret):
    """Calculate SECRET_HASH for Cognito authentication"""
    message = username + client_id
    dig = hmac.new(
        client_secret.encode('utf-8'),
        msg=message.encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()
    return base64.b64encode(dig).decode()

def authenticate_cognito(user_pool_id, client_id, username, password, client_secret=None, region='us-east-1'):
    """Authenticate with AWS Cognito and get JWT tokens"""
    try:
        client = boto3.client('cognito-idp', region_name=region)
        
        # Prepare auth parameters
        auth_parameters = {
            'USERNAME': username,
            'PASSWORD': password
        }
        
        # Add SECRET_HASH if client secret is provided
        if client_secret:
            secret_hash = calculate_secret_hash(username, client_id, client_secret)
            auth_parameters['SECRET_HASH'] = secret_hash
            
        # Log authentication attempt (without sensitive data)
        print(f"Attempting authentication for user {username} with client {client_id}")
        
        response = client.admin_initiate_auth(
            UserPoolId=user_pool_id,
            ClientId=client_id,
            AuthFlow='ADMIN_NO_SRP_AUTH',
            AuthParameters=auth_parameters
        )
        
        # Debug response (without sensitive data)
        print(f"Auth response keys: {list(response.keys())}")
        
        # Handle NEW_PASSWORD_REQUIRED challenge
        if 'ChallengeName' in response:
            if response['ChallengeName'] == 'NEW_PASSWORD_REQUIRED':
                return None, f"""Password change required. You can either:
                
                1. Set a permanent password via AWS CLI:
                ```
                aws cognito-idp admin-set-user-password \\
                    --user-pool-id {user_pool_id} \\
                    --username {username} \\
                    --password <new-password> \\
                    --permanent
                ```
                
                2. Or handle the challenge by providing a new password:
                ```
                aws cognito-idp admin-respond-to-auth-challenge \\
                    --user-pool-id {user_pool_id} \\
                    --client-id {client_id} \\
                    --challenge-name NEW_PASSWORD_REQUIRED \\
                    --challenge-responses USERNAME={username},NEW_PASSWORD=<new-password>
                ```
                
                Note: Password must meet the following requirements:
                - Minimum length of 8 characters
                - Contains at least 1 number
                - Contains at least 1 special character
                - Contains at least 1 uppercase letter
                - Contains at least 1 lowercase letter
                """
            else:
                return None, f"Authentication requires additional steps: {response['ChallengeName']}. Please complete the challenge in Cognito console."
        
        # Check if authentication result exists
        if 'AuthenticationResult' not in response:
            return None, f"Authentication failed: No authentication result received. Response contains: {list(response.keys())}"
            
        auth_result = response.get('AuthenticationResult')
        if not auth_result or not auth_result.get('AccessToken'):
            return None, f"Authentication failed: Invalid or empty authentication result. Available data: {list(auth_result.keys()) if auth_result else 'None'}"
            
        return auth_result, None
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_msg = e.response['Error']['Message']
        
        # Provide helpful error messages
        if error_code == 'NotAuthorizedException':
            if 'SECRET_HASH' in error_msg:
                return None, "Client secret is required but not provided. Please enter your App Client Secret."
            elif 'password' in error_msg.lower():
                return None, "Invalid username or password. Please check your credentials."
            else:
                return None, f"Authentication failed: {error_msg}"
        elif error_code == 'UserNotFoundException':
            return None, "User not found. Please check the username or create the user first."
        elif error_code == 'UserNotConfirmedException':
            return None, f"""User account is not confirmed. Run this command:
            
            aws cognito-idp admin-confirm-sign-up \\
                --user-pool-id {user_pool_id} \\
                --username {username}
            """
        elif error_code == 'PasswordResetRequiredException':
            return None, f"""Password reset required. Run this command to set a permanent password:
            
            aws cognito-idp admin-set-user-password \\
                --user-pool-id {user_pool_id} \\
                --username {username} \\
                --password <new-password> \\
                --permanent
            """
        elif error_code == 'InvalidParameterException':
            if 'Auth flow not enabled' in error_msg:
                return None, """Authentication flow not enabled. Enable ADMIN_USER_PASSWORD_AUTH:
                1. Go to AWS Cognito Console
                2. Select your User Pool
                3. Go to "App integration" tab
                4. Under "App clients and analytics", click on your app client
                5. Enable "ALLOW_ADMIN_USER_PASSWORD_AUTH"
                6. Click "Save changes"
                """
            return None, f"Invalid parameter: {error_msg}"
        else:
            return None, f"{error_code}: {error_msg}"
            
    except NoCredentialsError:
        return None, "AWS credentials not found. Please configure AWS CLI or set environment variables."
    except Exception as e:
        return None, f"Unexpected error: {str(e)}"

def test_api_endpoint(api_url, token, endpoint="/health"):
    """Test API endpoint with token"""
    try:
        headers = {}
        if token and endpoint != "/health":
            # Use ID Token for API calls instead of Access Token
            id_token = st.session_state.token_data.get('IdToken')
            if not id_token:
                return {
                    'success': False,
                    'error': "ID Token not found. Please generate tokens first."
                }
                
            headers['Authorization'] = f'Bearer {id_token}'  # Use ID Token instead of Access Token
            
            # Debug token information
            decoded, _ = decode_token(id_token)
            if decoded:
                print(f"Token claims: {json.dumps(decoded.get('payload', {}), indent=2)}")
        
        url = f"{api_url.rstrip('/')}{endpoint}"
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 401:
            return {
                'status_code': 401,
                'success': False,
                'error': "Unauthorized. Make sure you're using the ID Token and it contains the required claims (aud, exp, iss)."
            }
        
        return {
            'status_code': response.status_code,
            'success': response.status_code < 400,
            'data': response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text,
            'headers': dict(response.headers)
        }
    except requests.exceptions.RequestException as e:
        return {
            'success': False,
            'error': str(e)
        }

# Main app
def main():
    st.markdown('<h1 class="main-header">🔐 AWS Cognito Token Generator</h1>', unsafe_allow_html=True)
    st.markdown("Generate JWT tokens from AWS Cognito for testing your FastAPI authentication")
    
    # Sidebar for configuration
    with st.sidebar:
        st.header("⚙️ Configuration")
        
        # AWS Cognito Configuration
        st.subheader("AWS Cognito Settings")
        
        user_pool_id = st.text_input(
            "User Pool ID",
            value=st.session_state.cognito_config.get('user_pool_id', ''),
            placeholder="us-east-1_XXXXXXXXX",
            help="Found in AWS Cognito console under 'User pool overview'"
        )
        
        client_id = st.text_input(
            "App Client ID",
            value=st.session_state.cognito_config.get('client_id', ''),
            placeholder="your_client_id",
            help="Found in AWS Cognito console under 'App clients'"
        )
        
        client_secret = st.text_input(
            "App Client Secret (Optional)",
            value=st.session_state.cognito_config.get('client_secret', ''),
            type="password",
            placeholder="your_client_secret",
            help="Required if your app client is configured with a secret. Found in Cognito console under 'App clients'"
        )
        
        region = st.selectbox(
            "AWS Region",
            options=['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1', 'us-east-2', 'eu-central-1'],
            index=0
        )
        
        # Save config to session state
        st.session_state.cognito_config = {
            'user_pool_id': user_pool_id,
            'client_id': client_id,
            'client_secret': client_secret,
            'region': region
        }
        
        st.markdown("---")
        
        # API Testing Configuration
        st.subheader("API Testing")
        api_url = st.text_input(
            "FastAPI URL",
            value="http://localhost:8000",
            placeholder="https://your-api.com"
        )
        
        st.markdown("---")
        st.markdown("### 🔧 AWS Credentials")
        st.info("Make sure AWS CLI is configured or environment variables are set:\n\n"
                "• AWS_ACCESS_KEY_ID\n"
                "• AWS_SECRET_ACCESS_KEY\n"
                "• AWS_DEFAULT_REGION")
    
    # Main content
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.header("🔑 Generate Token")
        
        # Authentication form
        with st.form("auth_form"):
            username = st.text_input("Username", placeholder="Enter your username")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            
            submitted = st.form_submit_button("🚀 Generate Token", type="primary")
            
            if submitted:
                if not all([user_pool_id, client_id, username, password]):
                    st.error("Please fill in all required fields")
                else:
                    with st.spinner("Authenticating with AWS Cognito..."):
                        client_secret = st.session_state.cognito_config.get('client_secret')
                        auth_result, error = authenticate_cognito(
                            user_pool_id, client_id, username, password, client_secret, region
                        )
                        
                        if auth_result:
                            st.session_state.token_data = auth_result
                            st.markdown('<div class="success-box">✅ Authentication successful!</div>', 
                                       unsafe_allow_html=True)
                        else:
                            st.markdown(f'<div class="error-box">❌ Authentication failed: {error}</div>', 
                                       unsafe_allow_html=True)
    
    with col2:
        st.header("📋 Token Information")
        
        if st.session_state.token_data:
            auth_result = st.session_state.token_data
            
            # Token selection
            token_type = st.radio(
                "Select Token Type:",
                ["Access Token", "ID Token"],
                help="Access Token: For API authorization\nID Token: Contains user information"
            )
            
            selected_token = auth_result.get('AccessToken' if token_type == "Access Token" else 'IdToken')
            
            if selected_token:
                # Decode token
                decoded_token, decode_error = decode_token(selected_token)
                
                if decoded_token:
                    token_info = get_token_info(decoded_token)
                    
                    # Display token info
                    col_a, col_b = st.columns(2)
                    
                    with col_a:
                        st.metric("Username", token_info.get('username', 'N/A'))
                        st.metric("Client ID", token_info.get('client_id', 'N/A')[:20] + "..." if len(token_info.get('client_id', '')) > 20 else token_info.get('client_id', 'N/A'))
                        st.metric("Token Use", token_info.get('token_use', 'N/A'))
                    
                    with col_b:
                        st.metric("Email", token_info.get('email', 'N/A'))
                        st.metric("Expires At", token_info.get('expires_at', 'N/A'))
                        
                        if 'expired' in token_info:
                            if token_info['expired']:
                                st.error("🔴 Token Expired")
                            else:
                                st.success(f"🟢 Valid ({token_info.get('time_left', 'N/A')} left)")
                    
                    # Groups and Scopes
                    if token_info.get('groups'):
                        st.subheader("👥 Groups")
                        cols = st.columns(4)  # Create 4 columns for better layout
                        for i, group in enumerate(token_info['groups']):
                            cols[i % 4].markdown(
                                f"""<div style="display: inline-block; padding: 0.2rem 0.5rem; 
                                margin: 0.2rem; border-radius: 0.5rem; background-color: #e9ecef; 
                                font-size: 0.8rem;">{group}</div>""", 
                                unsafe_allow_html=True
                            )
                    
                    if token_info.get('scope'):
                        st.subheader("🔐 Scopes")
                        cols = st.columns(4)  # Create 4 columns for better layout
                        for i, scope in enumerate(token_info['scope']):
                            cols[i % 4].markdown(
                                f"""<div style="display: inline-block; padding: 0.2rem 0.5rem; 
                                margin: 0.2rem; border-radius: 0.5rem; background-color: #e9ecef; 
                                font-size: 0.8rem;">{scope}</div>""", 
                                unsafe_allow_html=True
                            )
                else:
                    st.error(f"Error decoding token: {decode_error}")
        else:
            st.info("👆 Generate a token to see information here")
    
    # Token display and copy section
    if st.session_state.token_data:
        st.header("📄 Raw Tokens")
        
        auth_result = st.session_state.token_data
        
        # Access Token
        if auth_result.get('AccessToken'):
            st.subheader("🔑 Access Token (Use this for API calls)")
            st.markdown('<div class="token-box">' + auth_result['AccessToken'] + '</div>', 
                       unsafe_allow_html=True)
            
            if st.button("📋 Copy Access Token", key="copy_access"):
                try:
                    pyperclip.copy(auth_result['AccessToken'])
                    st.success("✅ Access token copied to clipboard!")
                except:
                    st.info("💡 Manual copy: Select the token above and copy it manually")
        
        # ID Token
        if auth_result.get('IdToken'):
            st.subheader("🆔 ID Token")
            with st.expander("Show ID Token"):
                st.markdown('<div class="token-box">' + auth_result['IdToken'] + '</div>', 
                           unsafe_allow_html=True)
                
                if st.button("📋 Copy ID Token", key="copy_id"):
                    try:
                        pyperclip.copy(auth_result['IdToken'])
                        st.success("✅ ID token copied to clipboard!")
                    except:
                        st.info("💡 Manual copy: Select the token above and copy it manually")
        
        # Refresh Token
        if auth_result.get('RefreshToken'):
            st.subheader("🔄 Refresh Token")
            with st.expander("Show Refresh Token"):
                st.markdown('<div class="token-box">' + auth_result['RefreshToken'] + '</div>', 
                           unsafe_allow_html=True)
    
    # API Testing section
    if st.session_state.token_data and api_url:
        st.header("🧪 API Testing")
        
        # Add a warning about using ID Token
        st.info("""
        ℹ️ This tool uses the ID Token for API authentication because it contains the required 'aud' claim.
        Make sure your FastAPI app is configured to validate ID Tokens.
        """)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Test Endpoints")
            
            if not st.session_state.token_data.get('IdToken'):
                st.warning("⚠️ ID Token not found. Please generate tokens first.")
            else:
                endpoints = [
                    ("/health", "Public health check"),
                    ("/protected-health", "Protected health check"),
                    ("/aws_health?name=TestUser", "Lambda function call"),
                    ("/user/profile", "User profile"),
                    # ("/s3/buckets", "S3 buckets list"),
                    ("/admin/lambda?name=AdminUser", "Admin Lambda call")
                ]
            
            for endpoint, description in endpoints:
                if st.button(f"{endpoint}", key=f"test_{endpoint}"):
                    access_token = st.session_state.token_data.get('AccessToken')
                    
                    with st.spinner(f"Testing {endpoint}..."):
                        result = test_api_endpoint(api_url, access_token, endpoint)
                        st.session_state[f"test_result_{endpoint}"] = result
        
        with col2:
            st.subheader("Test Results")
            
            # Show latest test result
            for endpoint, _ in endpoints:
                if f"test_result_{endpoint}" in st.session_state:
                    result = st.session_state[f"test_result_{endpoint}"]
                    
                    if result.get('success'):
                        st.success(f"✅ {endpoint} - Status: {result.get('status_code')}")
                        with st.expander(f"Response for {endpoint}"):
                            st.json(result.get('data'))
                    else:
                        st.error(f"❌ {endpoint} - Error: {result.get('error', 'Unknown error')}")
    
    # Instructions
    st.header("📖 Instructions")
    
    with st.expander("🚀 How to use this tool"):
        st.markdown("""
        ### Step 1: Configure AWS Cognito
        1. Enter your **User Pool ID** (found in AWS Cognito console)
        2. Enter your **App Client ID** (found under App clients in Cognito)
        3. Select your **AWS Region**
        
        ### Step 2: Set up AWS Credentials
        Make sure you have AWS credentials configured:
        ```bash
        aws configure
        # or set environment variables:
        export AWS_ACCESS_KEY_ID="your-access-key"
        export AWS_SECRET_ACCESS_KEY="your-secret-key"
        export AWS_DEFAULT_REGION="us-east-1"
        ```
        
        ### Step 3: Generate Token
        1. Enter your Cognito username and password
        2. Click "Generate Token"
        3. Copy the **Access Token** for API calls
        
        ### Step 4: Use in FastAPI
        1. Go to your FastAPI Swagger UI (`http://your-api/docs`)
        2. Click the **"Authorize"** button (🔒)
        3. Paste the Access Token in the **HTTPBearer** field
        4. Click **"Authorize"**
        5. Test your protected endpoints!
        
        ### Step 5: Test APIs (Optional)
        - Enter your FastAPI URL in the sidebar
        - Use the "API Testing" section to test endpoints directly
        """)
    
    with st.expander("🔧 Troubleshooting"):
        st.markdown("""
        ### Common Issues:
        
        **"SECRET_HASH was not received"**
        - Your app client is configured with a secret
        - Enter your **App Client Secret** in the sidebar
        - Or disable the secret in Cognito console: App clients → Edit → Uncheck "Generate client secret"
        
        **"AWS credentials not found"**
        - Configure AWS CLI: `aws configure`
        - Or set environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
        
        **"UserNotFoundException"**
        - Create user in Cognito console or via CLI:
        ```bash
        aws cognito-idp admin-create-user \\
          --user-pool-id us-east-1_XXXXXXXXX \\
          --username testuser \\
          --user-attributes Name=email,Value=test@example.com \\
          --temporary-password TempPass123!
        ```
        
        **"NotAuthorizedException"**
        - Check username and password
        - User might need to change temporary password
        - User might be disabled
        - If using client secret, make sure it's correct
        
        **"UserNotConfirmedException"**
        - Confirm user account:
        ```bash
        aws cognito-idp admin-confirm-sign-up \\
          --user-pool-id us-east-1_XXXXXXXXX \\
          --username testuser
        ```
        
        **API calls failing**
        - Check if your FastAPI server is running
        - Verify the API URL is correct
        - Ensure token is not expired
        - Check if user has required roles/permissions
        
        ### How to disable client secret (if not needed):
        1. Go to AWS Cognito console
        2. Select your User Pool
        3. Go to "App clients" 
        4. Click "Edit" on your app client
        5. Uncheck "Generate client secret"
        6. Save changes
        """)
        

if __name__ == "__main__":
    main()