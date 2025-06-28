from flask_pymongo import PyMongo
from flask_login import LoginManager
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from flask_babel import Babel
from flask_compress import Compress
from pymongo import MongoClient
import certifi
import os
from dotenv import load_dotenv
import logging

# Set up logging
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Initialize MongoDB client
mongo_client = None
try:
    mongo_uri = os.getenv('MONGO_URI')
    if not mongo_uri:
        logger.error("MONGO_URI environment variable is not set")
        raise ValueError("MONGO_URI must be set in environment variables")
    mongo_client = MongoClient(
        mongo_uri,
        connect=True,
        connectTimeoutMS=30000,
        socketTimeoutMS=None,
        serverSelectionTimeoutMS=5000,
        maxPoolSize=50,
        minPoolSize=10,
        maxIdleTimeMS=30000,
        tlsCAFile=certifi.where(),
        retryWrites=True
    )
    logger.info("MongoDB client initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize MongoDB client: {str(e)}")
    raise RuntimeError(f"MongoDB initialization failed: {str(e)}")

# Initialize Flask extensions
login_manager = LoginManager()
flask_session = Session()
csrf = CSRFProtect()
babel = Babel()
compress = Compress()