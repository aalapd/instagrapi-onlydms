import json
import time
import logging
from datetime import datetime
from pathlib import Path
from instagrapi import Client
from instagrapi.exceptions import (
    ClientLoginRequired,
    ClientConnectionError,
    ClientForbiddenError,
    ClientThrottledError,
    ChallengeRequired,
)
from instagrapi.mixins.challenge import ChallengeChoice

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class InstagramClient:
    def __init__(self, session_dir: str = "sessions"):
        self.session_dir = Path(session_dir)
        self.session_dir.mkdir(exist_ok=True)
        self.client = None
        logging.info(f"Initialized InstagramClient with session directory: {self.session_dir}")

    def _get_session_path(self, username):
        path = self.session_dir / f"{username}_session.json"
        logging.info(f"Session path for {username}: {path}")
        return path

    def _save_session(self, username):
        try:
            session_path = self._get_session_path(username)
            self.client.dump_settings(session_path)
            logging.info(f"Session saved for {username} at {session_path}")
        except Exception as e:
            logging.error(f"Failed to save session for {username}: {str(e)}")
            raise Exception(f"Failed to save session: {str(e)}")

    def _load_session(self, username):
        session_path = self._get_session_path(username)
        if session_path.exists():
            try:
                with open(session_path) as f:
                    logging.info(f"Session loaded for {username} from {session_path}")
                    return json.load(f)
            except json.JSONDecodeError:
                logging.warning(f"Session file for {username} is corrupted. Deleting {session_path}")
                session_path.unlink()
                return None
        logging.info(f"No session found for {username}")
        return None

    def _handle_challenge(self, username, choice):
        """Handle verification challenge"""
        if not self.client.challenge_code_handler:
            code = input(f"Enter verification code for {username} ({choice}): ").strip()
            return code if code and code.isdigit() else None
        return self.client.challenge_code_handler(username, choice)

    def login(self, username, password):
        self.client = Client(verify=True)
        # Set up default challenge handler if none exists
        if not hasattr(self.client, 'challenge_code_handler'):
            self.client.challenge_code_handler = lambda username, choice: self._handle_challenge(username, choice)
        session_data = self._load_session(username)
        try:
            if session_data:
                self.client.set_settings(session_data)
                logging.info(f"Using existing session for {username}")
            else:
                logging.info(f"No existing session for {username}, logging in with credentials")
            try:
                self.client.login(username, password)
                self._save_session(username)
            except ChallengeRequired:
                logging.info(f"Challenge required for {username}")
                self.client.challenge_resolve(self.client.last_json)
                self._save_session(username)
        except (ClientLoginRequired, ClientForbiddenError):
            logging.warning(f"Session for {username} is invalid, re-logging in")
            self.client.set_settings({})
            self.client.login(username, password)
            self._save_session(username)
        except Exception as e:
            logging.error(f"Login failed for {username}: {str(e)}")
            raise Exception(f"Login failed: {str(e)}")

    def fetch_conversations(self, username=None, filter_username=None, thread_limit=20, message_limit=50):
        if not self.client:
            logging.error("Client not initialized. Call login() first.")
            raise RuntimeError("Client not initialized. Call login() first.")
        conversations = []
        try:
            if filter_username and filter_username != "":
                try:
                    logging.info(f"Fetching conversation with user: {filter_username}")
                    user_info = self.client.user_info_by_username(filter_username)
                    user_id = user_info.pk
                    thread = self.client.direct_thread_by_participants([user_id])
                    messages = self.client.direct_messages(thread.id, amount=message_limit)
                    conversation = {
                        "thread_id": thread.id,
                        "participants": [user.username for user in thread.users],
                        "messages": [
                            {
                                "timestamp": message.timestamp.isoformat()
                                if isinstance(message.timestamp, datetime)
                                else datetime.fromtimestamp(int(message.timestamp)).isoformat(),
                                "user_id": message.user_id,
                                "text": message.text if message.text else "",
                            }
                            for message in messages
                        ],
                    }
                    conversations.append(conversation)
                    logging.info(f"Fetched conversation with {filter_username}")
                    time.sleep(1)
                except Exception as e:
                    logging.error(f"Failed to fetch conversation with user {filter_username}: {str(e)}")
                    return json.dumps({"error": "Failed to fetch conversation with user", "details": str(e)})
            else:
                logging.info(f"Fetching conversations with thread limit: {thread_limit} and message limit: {message_limit}")
                threads = self.client.direct_threads(amount=thread_limit)
                for thread in threads:
                    messages = self.client.direct_messages(thread.id, amount=message_limit)
                    conversation = {
                        "thread_id": thread.id,
                        "participants": [user.username for user in thread.users],
                        "messages": [
                            {
                                "timestamp": message.timestamp.isoformat()
                                if isinstance(message.timestamp, datetime)
                                else datetime.fromtimestamp(int(message.timestamp)).isoformat(),
                                "user_id": message.user_id,
                                "text": message.text if message.text else "",
                            }
                            for message in messages
                        ],
                    }
                    conversations.append(conversation)
                    logging.info(f"Fetched conversation from thread {thread.id}")
                    time.sleep(1)
            return json.dumps(conversations)
        except Exception as e:
            logging.error(f"Failed to fetch conversations: {str(e)}")
            return json.dumps({"error": "Failed to fetch conversations", "details": str(e)})
