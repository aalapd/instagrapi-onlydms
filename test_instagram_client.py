# To run this test use the following command:
# pytest -sv test_instagram_client.py

import pytest
import json
import os
from pathlib import Path
from datetime import datetime
from instagrapi.exceptions import (
    ClientLoginRequired,
    ClientConnectionError,
    ClientForbiddenError,
    ClientThrottledError,
    ChallengeRequired
)
from instagrapi.mixins.challenge import ChallengeChoice
from instagrapi import Client
from instagram_client import InstagramClient

# Test credentials - replace with your test account
USERNAME = os.getenv("INSTA_USER", "miji.chaos")
PASSWORD = os.getenv("INSTA_PASS", "pybot4lyf!")

def get_code_from_sms(username):
    """Handler for SMS verification"""
    code = input(f"Enter SMS verification code for {username}: ").strip()
    return code if code and code.isdigit() else None

def get_code_from_email(username):
    """Handler for email verification"""
    code = input(f"Enter email verification code for {username}: ").strip()
    return code if code and code.isdigit() else None

def challenge_code_handler(username, choice):
    """Handle verification challenge"""
    if choice == ChallengeChoice.SMS:
        return get_code_from_sms(username)
    elif choice == ChallengeChoice.EMAIL:
        return get_code_from_email(username)
    return False

@pytest.fixture(scope="session")
def temp_session_dir(tmp_path_factory):
    """Create a temporary directory for test sessions"""
    return tmp_path_factory.mktemp("test_sessions")

@pytest.fixture(scope="session")
def instagram_client(temp_session_dir):
    """Create and configure InstagramClient instance"""
    client = InstagramClient(session_dir=str(temp_session_dir))
    # Set up challenge handler
    if not client.client:
        client.client = Client()
    client.client.challenge_code_handler = challenge_code_handler
    return client

@pytest.fixture(scope="session")
def logged_in_client(instagram_client):
    """Provide a logged-in client instance"""
    try:
        instagram_client.login(USERNAME, PASSWORD)
        return instagram_client
    except Exception as e:
        pytest.fail(f"Failed to log in: {str(e)}")

def test_session_management(temp_session_dir, instagram_client):
    """Test session saving and loading"""
    # Test session path creation
    session_path = instagram_client._get_session_path(USERNAME)
    assert isinstance(session_path, Path)
    assert str(temp_session_dir) in str(session_path)

    # Test session saving
    try:
        instagram_client.login(USERNAME, PASSWORD)
        assert session_path.exists(), "Session file should be created after login"
    except Exception as e:
        pytest.fail(f"Login failed: {str(e)}")

    # Test session loading
    session_data = instagram_client._load_session(USERNAME)
    assert session_data is not None, "Should load valid session data"
    assert isinstance(session_data, dict), "Session data should be a dictionary"

def test_login_with_session_reuse(instagram_client):
    """Test login with session reuse"""
    try:
        # First login should create session
        instagram_client.login(USERNAME, PASSWORD)
        
        # Second login should reuse session
        instagram_client.login(USERNAME, PASSWORD)
    except Exception as e:
        pytest.fail(f"Login with session reuse failed: {str(e)}")

def test_fetch_conversations_multiple(logged_in_client):
    """Test fetching multiple conversations"""
    try:
        result = logged_in_client.fetch_conversations(thread_limit=5)
        conversations = json.loads(result)
        
        assert isinstance(conversations, list), "Should return a list"
        if conversations:
            for conversation in conversations:
                assert "thread_id" in conversation
                assert "participants" in conversation
                assert "messages" in conversation
                assert isinstance(conversation["messages"], list)
                
                # Verify message structure
                if conversation["messages"]:
                    message = conversation["messages"][0]
                    assert "timestamp" in message
                    assert "user_id" in message
                    assert "text" in message
                    
                    # Verify timestamp format
                    try:
                        datetime.fromisoformat(message["timestamp"])
                    except ValueError:
                        pytest.fail("Invalid timestamp format")
    except Exception as e:
        pytest.fail(f"Failed to fetch multiple conversations: {str(e)}")

def test_error_handling(instagram_client):
    """Test error handling scenarios"""
    # Test invalid credentials
    with pytest.raises(Exception) as exc_info:
        instagram_client.login("invalid_username", "invalid_password")
    assert "Login failed" in str(exc_info.value)

    # Test fetching conversations without login
    instagram_client.client = None
    with pytest.raises(RuntimeError) as exc_info:
        instagram_client.fetch_conversations()
    assert "Client not initialized" in str(exc_info.value)

if __name__ == "__main__":
    pytest.main(["-sv", __file__])
