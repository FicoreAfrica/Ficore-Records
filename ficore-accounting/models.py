from datetime import datetime
from pymongo import ASCENDING, DESCENDING
from utils import get_mongo_db, check_mongodb_connection
from extensions import mongo_client
from logging import getLogger

logger = getLogger('ficore_app')

# Sample courses data
SAMPLE_COURSES = [
    {
        'id': 'budgeting_learning_101',
        'title_key': 'learning_hub_course_budgeting101_title',
        'title_en': 'Budgeting Learning 101',
        'title_ha': 'Tsarin Kudi 101',
        'description_en': 'Learn the basics of budgeting.',
        'description_ha': 'Koyon asalin tsarin kudi.',
        'is_premium': False
    },
    {
        'id': 'financial_quiz',
        'title_key': 'learning_hub_course_financial_quiz_title',
        'title_en': 'Financial Quiz',
        'title_ha': 'Jarabawar Kudi',
        'description_en': 'Test your financial knowledge.',
        'description_ha': 'Gwada ilimin ku na kudi.',
        'is_premium': False
    },
    {
        'id': 'savings_basics',
        'title_key': 'learning_hub_course_savings_basics_title',
        'title_en': 'Savings Basics',
        'title_ha': 'Asalin Tattara Kudi',
        'description_en': 'Understand how to save effectively.',
        'description_ha': 'Fahimci yadda ake tattara kudi yadda ya kamata.',
        'is_premium': False
    }
]

def initialize_database(app):
    max_retries = 3
    for attempt in range(max_retries):
        try:
            if check_mongodb_connection(mongo_client, app):
                logger.info(f"Attempt {attempt + 1}/{max_retries} - MongoDB connection established")
                break
            else:
                logger.warning(f"Attempt {attempt + 1}/{max_retries} - MongoDB connection not ready")
                if attempt == max_retries - 1:
                    logger.error("Max retries reached: MongoDB connection not established")
                    raise RuntimeError("MongoDB connection failed after max retries")
        except Exception as e:
            logger.error(f"Failed to initialize database (attempt {attempt + 1}/{max_retries}): {e}", exc_info=True)
            if attempt == max_retries - 1:
                raise
    try:
        db_instance = get_mongo_db()
        try:
            db_instance.command('ping')
        except Exception as e:
            logger.error(f"MongoDB client is closed before database operations: {str(e)}")
            raise RuntimeError("MongoDB client is closed")
        logger.info(f"MongoDB database: {db_instance.name}")
        collections = db_instance.list_collection_names()
        collection_schemas = {
            'users': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['_id', 'email', 'password', 'role'],
                        'properties': {
                            '_id': {'bsonType': 'string'},
                            'email': {'bsonType': 'string', 'pattern': r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'},
                            'password': {'bsonType': 'string'},
                            'role': {'enum': ['personal', 'trader', 'agent', 'admin']},
                            'coin_balance': {'bsonType': 'int', 'minimum': 0},
                            'language': {'enum': ['en', 'ha']},
                            'created_at': {'bsonType': 'date'},
                            'display_name': {'bsonType': ['string', 'null']},
                            'is_admin': {'bsonType': 'bool'},
                            'setup_complete': {'bsonType': 'bool'},
                            'reset_token': {'bsonType': ['string', 'null']},
                            'reset_token_expiry': {'bsonType': ['date', 'null']},
                            'otp': {'bsonType': ['string', 'null']},
                            'otp_expiry': {'bsonType': ['date', 'null']},
                            'business_details': {
                                'bsonType': ['object', 'null'],
                                'properties': {
                                    'name': {'bsonType': 'string'},
                                    'address': {'bsonType': 'string'},
                                    'industry': {'bsonType': 'string'},
                                    'products_services': {'bsonType': 'string'},
                                    'phone_number': {'bsonType': 'string'}
                                }
                            },
                            'personal_details': {
                                'bsonType': ['object', 'null'],
                                'properties': {
                                    'first_name': {'bsonType': 'string'},
                                    'last_name': {'bsonType': 'string'},
                                    'phone_number': {'bsonType': 'string'},
                                    'address': {'bsonType': 'string'}
                                }
                            },
                            'agent_details': {
                                'bsonType': ['object', 'null'],
                                'properties': {
                                    'agent_name': {'bsonType': 'string'},
                                    'agent_id': {'bsonType': 'string'},
                                    'area': {'bsonType': 'string'},
                                    'role': {'bsonType': 'string'},
                                    'email': {'bsonType': 'string'},
                                    'phone': {'bsonType': 'string'}
                                }
                            }
                        }
                    }
                },
                'indexes': [
                    {'key': [('email', ASCENDING)], 'unique': True},
                    {'key': [('reset_token', ASCENDING)], 'sparse': True},
                    {'key': [('role', ASCENDING)]}
                ]
            },
            'records': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['user_id', 'name', 'amount_owed', 'type', 'created_at'],
                        'properties': {
                            'user_id': {'bsonType': 'string'},
                            'name': {'bsonType': 'string'},
                            'amount_owed': {'bsonType': 'double', 'minimum': 0},
                            'type': {'enum': ['debtor', 'creditor']},
                            'created_at': {'bsonType': 'date'},
                            'contact': {'bsonType': ['string', 'null']},
                            'description': {'bsonType': ['string', 'null']},
                            'reminder_count': {'bsonType': ['int', 'null'], 'minimum': 0}
                        }
                    }
                },
                'indexes': [
                    {'key': [('user_id', ASCENDING), ('type', ASCENDING)]},
                    {'key': [('created_at', DESCENDING)]}
                ]
            },
            'cashflows': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['user_id', 'amount', 'party_name', 'type', 'created_at'],
                        'properties': {
                            'user_id': {'bsonType': 'string'},
                            'amount': {'bsonType': 'double', 'minimum': 0},
                            'party_name': {'bsonType': 'string'},
                            'type': {'enum': ['payment', 'receipt']},
                            'created_at': {'bsonType': 'date'},
                            'method': {'enum': ['card', 'bank', 'cash', None]},
                            'category': {'bsonType': ['string', 'null']},
                            'file_id': {'bsonType': ['objectId', 'null']},
                            'filename': {'bsonType': ['string', 'null']}
                        }
                    }
                },
                'indexes': [
                    {'key': [('user_id', ASCENDING), ('type', ASCENDING)]},
                    {'key': [('created_at', DESCENDING)]}
                ]
            },
            'inventory': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['user_id', 'item_name', 'qty', 'created_at'],
                        'properties': {
                            'user_id': {'bsonType': 'string'},
                            'item_name': {'bsonType': 'string'},
                            'qty': {'bsonType': 'int', 'minimum': 0},
                            'created_at': {'bsonType': 'date'},
                            'unit': {'bsonType': ['string', 'null']},
                            'buying_price': {'bsonType': ['double', 'null'], 'minimum': 0},
                            'selling_price': {'bsonType': ['double', 'null'], 'minimum': 0},
                            'threshold': {'bsonType': ['int', 'null'], 'minimum': 0},
                            'updated_at': {'bsonType': ['date', 'null']}
                        }
                    }
                },
                'indexes': [
                    {'key': [('user_id', ASCENDING)]},
                    {'key': [('created_at', DESCENDING)]}
                ]
            },
            'coin_transactions': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['user_id', 'amount', 'type', 'date'],
                        'properties': {
                            'user_id': {'bsonType': 'string'},
                            'amount': {'bsonType': 'int'},
                            'type': {'enum': ['purchase', 'spend', 'credit', 'admin_credit']},
                            'date': {'bsonType': 'date'},
                            'ref': {'bsonType': ['string', 'null']},
                            'facilitated_by_agent': {'bsonType': ['string', 'null']},
                            'payment_method': {'bsonType': ['string', 'null']},
                            'cash_amount': {'bsonType': ['double', 'null']},
                            'notes': {'bsonType': ['string', 'null']}
                        }
                    }
                },
                'indexes': [
                    {'key': [('user_id', ASCENDING)]},
                    {'key': [('date', DESCENDING)]},
                    {'key': [('facilitated_by_agent', ASCENDING)], 'sparse': True}
                ]
            },
            'agent_activities': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['agent_id', 'activity_type', 'timestamp'],
                        'properties': {
                            'agent_id': {'bsonType': 'string'},
                            'activity_type': {'enum': ['trader_registration', 'token_facilitation', 'report_generation', 'trader_assistance']},
                            'trader_id': {'bsonType': ['string', 'null']},
                            'details': {'bsonType': ['object', 'null']},
                            'timestamp': {'bsonType': 'date'}
                        }
                    }
                },
                'indexes': [
                    {'key': [('agent_id', ASCENDING)]},
                    {'key': [('timestamp', DESCENDING)]},
                    {'key': [('trader_id', ASCENDING)], 'sparse': True}
                ]
            },
            'audit_logs': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['admin_id', 'action', 'details', 'timestamp'],
                        'properties': {
                            'admin_id': {'bsonType': 'string'},
                            'action': {'bsonType': 'string'},
                            'details': {'bsonType': ['object', 'null']},
                            'timestamp': {'bsonType': 'date'}
                        }
                    }
                },
                'indexes': [
                    {'key': [('timestamp', DESCENDING)]}
                ]
            },
            'feedback': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['user_id', 'tool_name', 'rating', 'timestamp'],
                        'properties': {
                            'user_id': {'bsonType': 'string'},
                            'tool_name': {'bsonType': 'string'},
                            'rating': {'bsonType': 'int', 'minimum': 1, 'maximum': 5},
                            'comment': {'bsonType': ['string', 'null']},
                            'timestamp': {'bsonType': 'date'}
                        }
                    }
                },
                'indexes': [
                    {'key': [('user_id', ASCENDING)], 'sparse': True},
                    {'key': [('timestamp', DESCENDING)]}
                ]
            },
            'reminder_logs': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['user_id', 'debt_id', 'recipient', 'message', 'type', 'sent_at', 'notification_id', 'read_status'],
                        'properties': {
                            'user_id': {'bsonType': 'string'},
                            'debt_id': {'bsonType': 'string'},
                            'recipient': {'bsonType': 'string'},
                            'message': {'bsonType': 'string'},
                            'type': {'enum': ['sms', 'whatsapp']},
                            'sent_at': {'bsonType': 'date'},
                            'api_response': {'bsonType': ['object', 'null']},
                            'notification_id': {'bsonType': 'string'},
                            'read_status': {'bsonType': 'bool'}
                        }
                    }
                },
                'indexes': [
                    {'key': [('user_id', ASCENDING)]},
                    {'key': [('debt_id', ASCENDING)]},
                    {'key': [('sent_at', DESCENDING)]},
                    {'key': [('notification_id', ASCENDING)], 'unique': True}
                ]
            },
            'sessions': {
                'validator': {},
                'indexes': [
                    {'key': [('expiration', ASCENDING)], 'expireAfterSeconds': 0, 'name': 'expiration_1'}
                ]
            },
            'courses': {
                'indexes': [
                    {'key': [('id', ASCENDING)], 'unique': True}
                ]
            },
            'content_metadata': {
                'indexes': [
                    {'key': [('course_id', ASCENDING), ('lesson_id', ASCENDING)], 'unique': True}
                ]
            },
            'financial_health': {
                'indexes': [
                    {'key': [('session_id', ASCENDING)]},
                    {'key': [('user_id', ASCENDING)]}
                ]
            },
            'budgets': {
                'indexes': [
                    {'key': [('session_id', ASCENDING)]},
                    {'key': [('user_id', ASCENDING)]}
                ]
            },
            'bills': {
                'indexes': [
                    {'key': [('session_id', ASCENDING)]},
                    {'key': [('user_id', ASCENDING)]},
                    {'key': [('user_email', ASCENDING)]},
                    {'key': [('status', ASCENDING)]},
                    {'key': [('due_date', ASCENDING)]}
                ]
            },
            'net_worth': {
                'indexes': [
                    {'key': [('session_id', ASCENDING)]},
                    {'key': [('user_id', ASCENDING)]}
                ]
            },
            'emergency_funds': {
                'indexes': [
                    {'key': [('session_id', ASCENDING)]},
                    {'key': [('user_id', ASCENDING)]}
                ]
            },
            'learning_progress': {
                'indexes': [
                    {'key': [('user_id', ASCENDING), ('course_id', ASCENDING)], 'unique': True},
                    {'key': [('session_id', ASCENDING), ('course_id', ASCENDING)], 'unique': True},
                    {'key': [('session_id', ASCENDING)]},
                    {'key': [('user_id', ASCENDING)]}
                ]
            },
            'quiz_results': {
                'indexes': [
                    {'key': [('session_id', ASCENDING)]},
                    {'key': [('user_id', ASCENDING)]}
                ]
            },
            'tool_usage': {
                'indexes': [
                    {'key': [('session_id', ASCENDING)]},
                    {'key': [('user_id', ASCENDING)]},
                    {'key': [('tool_name', ASCENDING)]}
                ]
            },
            'reset_tokens': {
                'indexes': [
                    {'key': [('token', ASCENDING)], 'unique': True}
                ]
            }
        }
        for collection_name, config in collection_schemas.items():
            if collection_name not in collections:
                db_instance.create_collection(collection_name, validator=config.get('validator', {}))
                logger.info(f"Created collection: {collection_name}")
            existing_indexes = db_instance[collection_name].index_information()
            for index in config.get('indexes', []):
                keys = index['key']
                options = {k: v for k, v in index.items() if k != 'key'}
                index_key_tuple = tuple(keys)
                index_name = options.get('name', '')
                index_exists = False
                for existing_index_name, existing_index_info in existing_indexes.items():
                    if tuple(existing_index_info['key']) == index_key_tuple:
                        existing_options = {k: v for k, v in existing_index_info.items() if k not in ['key', 'v', 'ns']}
                        if existing_options == options:
                            logger.info(f"Index already exists on {collection_name}: {keys} with options {options}")
                            index_exists = True
                        else:
                            logger.warning(f"Index conflict on {collection_name}: {keys}. Existing options: {existing_options}, Requested: {options}")
                        break
                if not index_exists:
                    if collection_name == 'sessions' and index_name == 'expiration_1':
                        if 'expiration_1' not in existing_indexes:
                            db_instance[collection_name].create_index(keys, **options)
                            logger.info(f"Created index on {collection_name}: {keys} with options {options}")
                    else:
                        db_instance[collection_name].create_index(keys, **options)
                        logger.info(f"Created index on {collection_name}: {keys} with options {options}")
        courses_collection = db_instance.courses
        if courses_collection.count_documents({}) == 0:
            for course in SAMPLE_COURSES:
                courses_collection.insert_one(course)
            logger.info("Initialized courses in MongoDB")
        app.config['COURSES'] = list(courses_collection.find({}, {'_id': 0}))
    except Exception as e:
        logger.error(f"Failed to initialize database indexes/courses: {str(e)}", exc_info=True)
        raise